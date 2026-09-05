package com.b3xal.headeranalyzer;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.EnhancedCapability;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.scanner.scancheck.ScanCheckType;
import com.b3xal.headeranalyzer.analyzer.ActiveHeaderScanner;
import com.b3xal.headeranalyzer.analyzer.BulkAnalyzer;
import com.b3xal.headeranalyzer.analyzer.HeaderAnalysisEngine;
import com.b3xal.headeranalyzer.analyzer.JwtActiveProbe;
import com.b3xal.headeranalyzer.analyzer.RetestTracker;
import com.b3xal.headeranalyzer.analyzer.SessionInvalidationProbe;
import com.b3xal.headeranalyzer.analyzer.ResultStore;
import com.b3xal.headeranalyzer.analyzer.RuleStore;
import com.b3xal.headeranalyzer.browser.BrowserBridgeServer;
import com.b3xal.headeranalyzer.browser.ScopeHostTracker;
import com.b3xal.headeranalyzer.config.QuimeraSettings;
import com.b3xal.headeranalyzer.context.ContextMenuProvider;
import com.b3xal.headeranalyzer.model.DomainData;
import com.b3xal.headeranalyzer.proxy.QuimeraHttpHandler;
import com.b3xal.headeranalyzer.scanner.HeaderPassiveScanner;
import com.b3xal.headeranalyzer.ui.QuimeraTab;
import com.b3xal.headeranalyzer.util.SafeLogging;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class HeaderAnalyzerExtension implements BurpExtension {

    // Declares that the Advisory panel's opt-in "AI Analysis" button uses api.ai(). This is what
    // makes Burp show its own "allow this extension to use AI?" consent prompt on load, instead
    // of the button silently failing/misbehaving the first time it's clicked without Burp ever
    // having asked. See DetailPanel.runAiAnalysis().
    @Override
    public Set<EnhancedCapability> enhancedCapabilities() {
        return Set.of(EnhancedCapability.AI_FEATURES);
    }

    @Override
    public void initialize(MontoyaApi api) {
        try {
            doInitialize(api);
        } catch (Exception ex) {
            // If anything above throws uncaught, Burp marks the extension as failed to load and
            // NOTHING gets registered, including the HTTP handler, which looks identical to
            // "the extension loaded fine but silently captures nothing". Make that unmistakable.
            SafeLogging.error(api, "[Quimera] FAILED TO INITIALIZE: " + ex);
            throw ex;
        }
    }

    private void doInitialize(MontoyaApi api) {
        api.extension().setName("Quimera");

        PersistedObject persisted = api.persistence().extensionData();

        ConcurrentHashMap<String, DomainData> domainStore = new ConcurrentHashMap<>();
        RetestTracker    retestTracker = new RetestTracker();
        RuleStore        ruleStore     = new RuleStore(persisted);
        ResultStore      resultStore   = new ResultStore(persisted, api);
        // Populate domainStore with whatever finding-bearing results survived from a previous
        // session BEFORE the tab/UI is built, so the Logger/Cookies/Report tabs open already
        // showing them instead of looking freshly empty until new traffic arrives.
        resultStore.loadInto(domainStore);
        QuimeraSettings  settings      = new QuimeraSettings(persisted);
        HeaderAnalysisEngine engine    = new HeaderAnalysisEngine(ruleStore, settings);
        ActiveHeaderScanner activeScanner = new ActiveHeaderScanner(api, engine, settings);
        JwtActiveProbe   jwtActiveProbe = new JwtActiveProbe(api, engine);
        SessionInvalidationProbe sessionInvalidationProbe = new SessionInvalidationProbe(api, engine);
        BulkAnalyzer     bulkAnalyzer  = new BulkAnalyzer(api, engine, activeScanner, settings);
        ScopeHostTracker scopeHostTracker = new ScopeHostTracker(api.scope()::isInScope);

        // BrowserBridgeServer is constructed after the tab (its onResult callback feeds
        // tab::onResultAdded), but the tab's Settings > Browser Bridge dialog needs a way to
        // restart THAT server when its port changes, a one-element array is the standard pattern
        // for this construction-order cycle: the tab captures a lambda closing over the array now,
        // the array is filled in once browserServer actually exists a few lines below.
        BrowserBridgeServer[] browserServerHolder = new BrowserBridgeServer[1];
        Runnable restartBrowserBridge = () -> {
            if (browserServerHolder[0] != null) browserServerHolder[0].restart();
        };
        java.util.function.BooleanSupplier isBrowserBridgeRunning =
                () -> browserServerHolder[0] != null && browserServerHolder[0].isRunning();

        QuimeraTab tab = new QuimeraTab(api, domainStore, retestTracker, resultStore, engine, ruleStore, settings,
                activeScanner, bulkAnalyzer, sessionInvalidationProbe, restartBrowserBridge, isBrowserBridgeRunning);
        ContextMenuProvider contextMenu = new ContextMenuProvider(api, engine, activeScanner, bulkAnalyzer, settings, tab);

        BrowserBridgeServer browserServer = new BrowserBridgeServer(
                api, settings, engine, tab::onResultAdded, scopeHostTracker::snapshot);
        browserServerHolder[0] = browserServer;
        if (settings.isBrowserBridgeEnabled()) browserServer.start();

        // Register UI tab
        api.userInterface().registerSuiteTab(tab.caption(), tab.uiComponent());

        // Universal passive listener, feeds the Logger from every configured Burp tool
        // (Proxy, Repeater, Intruder, Scanner, Target... configurable in Settings, all on by default).
        // Also owns the opt-in auto-active-scan (Settings > "Automatically probe every new URL..."),
        // see QuimeraHttpHandler javadoc.
        QuimeraHttpHandler httpHandler = new QuimeraHttpHandler(api, engine, settings, tab, activeScanner,
                jwtActiveProbe, sessionInvalidationProbe, scopeHostTracker);
        api.http().registerHttpHandler(httpHandler);
        SafeLogging.output(api, "[Quimera] HTTP handler registered.");

        // Burp's native passive scan check, feeds the Issues tab only (see HeaderPassiveScanner javadoc)
        api.scanner().registerPassiveScanCheck(
                new HeaderPassiveScanner(api, engine, settings),
                ScanCheckType.PER_REQUEST);

        // Right-click context menu, single/bulk analyze, active header scan
        api.userInterface().registerContextMenuItemsProvider(contextMenu);

        // Clean unloading: shut down all background thread pools (BApp Store criterion 6)
        api.extension().registerUnloadingHandler(() -> {
            tab.shutdown();
            contextMenu.shutdown();
            bulkAnalyzer.shutdown();
            httpHandler.shutdown();
            browserServer.shutdown();
            SafeLogging.output(api, "[Quimera] Unloaded cleanly.");
        });

        SafeLogging.output(api, "[Quimera] Loaded. Passive listening tools: " + settings.getEnabledTools() +
                " | Restrict to scope: " + settings.isRestrictToScope() +
                " | Rules: " + ruleStore.all().size() + " | Active scan probes ready." +
                " | Browser bridge: " + (browserServer.isRunning()
                        ? "listening on 127.0.0.1:" + settings.getBrowserBridgePort() : "disabled"));
    }
}
