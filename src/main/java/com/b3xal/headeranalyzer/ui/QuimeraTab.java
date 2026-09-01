package com.b3xal.headeranalyzer.ui;

import burp.api.montoya.MontoyaApi;
import com.b3xal.headeranalyzer.analyzer.ActiveHeaderScanner;
import com.b3xal.headeranalyzer.analyzer.BulkAnalyzer;
import com.b3xal.headeranalyzer.analyzer.HeaderAnalysisEngine;
import com.b3xal.headeranalyzer.analyzer.RetestTracker;
import com.b3xal.headeranalyzer.analyzer.RuleStore;
import com.b3xal.headeranalyzer.analyzer.SessionInvalidationProbe;
import com.b3xal.headeranalyzer.config.QuimeraSettings;
import com.b3xal.headeranalyzer.model.DomainData;
import com.b3xal.headeranalyzer.model.Severity;
import com.b3xal.headeranalyzer.model.UrlAnalysisResult;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Suite tab shell, Logger-centric redesign (Quimera 2.0).
 *
 * Tabs: Headers (header findings/technology, main workspace), Cookies (Set-Cookie inventory, kept
 * separate so cookie flags don't mix into the header issue list), Rules (detection rule editor),
 * Report (evidence for screenshots), Settings. A thin status bar at the bottom shows the severity
 * legend and live totals; the Headers tab itself owns the Analyze/Clear workflow buttons, Clear
 * wipes both Headers and Cookies since they're fed from the same captured traffic.
 */
public final class QuimeraTab {

    private static final String TAB_NAME = "Quimera";

    private final MontoyaApi api;
    private final ConcurrentHashMap<String, DomainData> domainStore;
    private final RetestTracker retestTracker;
    private final HeaderAnalysisEngine engine;
    private final SessionInvalidationProbe sessionInvalidationProbe;
    private final QuimeraSettings settings;

    private final JPanel        root;
    private final LoggerPanel   loggerPanel;
    private final DetailPanel   detailPanel;
    private final CookiePanel   cookiePanel;
    private final DetailPanel   cookieDetailPanel;
    private final RulesPanel    rulesPanel;
    private final ReportPanel   reportPanel;
    private final SettingsPanel settingsPanel;

    private final JButton autoActiveScanToggle = new JButton();

    // Report tab is a hidden easter egg: absent from the tab strip unless "factum" (case-
    // insensitive) is one of the entries in Settings' "Header names to never report" list, the
    // list re-purposed as an unlock code rather than adding a whole new settings field just for
    // this. Reactive: adding/removing "factum" and hitting Apply toggles the tab live, doesn't
    // require a restart. Adding "factum" there has zero effect on real suppression, no HTTP
    // header is ever actually named that.
    private static final String REPORT_TAB_UNLOCK = "factum";
    private final JTabbedPane tabs;
    private boolean reportTabVisible = false;

    private int totalUrls     = 0;
    private int totalFindings = 0;
    private int totalHosts    = 0;
    private final JLabel statsLabel = new JLabel();

    public QuimeraTab(MontoyaApi api,
                       ConcurrentHashMap<String, DomainData> domainStore,
                       RetestTracker retestTracker,
                       HeaderAnalysisEngine engine,
                       RuleStore ruleStore,
                       QuimeraSettings settings,
                       ActiveHeaderScanner activeScanner,
                       BulkAnalyzer bulkAnalyzer,
                       SessionInvalidationProbe sessionInvalidationProbe) {
        this(api, domainStore, retestTracker, engine, ruleStore, settings, activeScanner, bulkAnalyzer,
                sessionInvalidationProbe, () -> {}, () -> false);
    }

    public QuimeraTab(MontoyaApi api,
                       ConcurrentHashMap<String, DomainData> domainStore,
                       RetestTracker retestTracker,
                       HeaderAnalysisEngine engine,
                       RuleStore ruleStore,
                       QuimeraSettings settings,
                       ActiveHeaderScanner activeScanner,
                       BulkAnalyzer bulkAnalyzer,
                       SessionInvalidationProbe sessionInvalidationProbe,
                       Runnable onBrowserBridgeApplied,
                       java.util.function.BooleanSupplier browserBridgeRunning) {
        this.api           = api;
        this.domainStore   = domainStore;
        this.retestTracker = retestTracker;
        this.engine        = engine;
        this.sessionInvalidationProbe = sessionInvalidationProbe;
        this.settings      = settings;

        detailPanel       = new DetailPanel(api, retestTracker, engine, activeScanner, this::onResultAdded);
        cookieDetailPanel = new DetailPanel(api, retestTracker, engine, activeScanner, this::onResultAdded);
        reportPanel   = new ReportPanel(domainStore, retestTracker, api, engine);
        loggerPanel   = new LoggerPanel(api, bulkAnalyzer, settings);
        cookiePanel   = new CookiePanel();
        rulesPanel    = new RulesPanel(ruleStore);
        settingsPanel = new SettingsPanel(api, settings, this::onSettingsApplied,
                onBrowserBridgeApplied, browserBridgeRunning);

        // Row selection in either Logger drives its own Detail panel plus the shared Report panel
        // (Report is scoped per-URL, not per-tab, so it always reflects whatever was last clicked).
        // headerHint is the currently-open issue's header name (if any), so the response
        // auto-highlights it.
        loggerPanel.setOnRowSelected((result, headerHint, issueNameHint) -> {
            detailPanel.show(result, headerHint, issueNameHint);
            reportPanel.show(result);
        });
        loggerPanel.setOnResultProduced(this::onResultAdded);
        loggerPanel.setOnClearAll(this::clearAll);

        cookiePanel.setOnRowSelected((result, headerHint, issueNameHint, isRequestHeader) -> {
            cookieDetailPanel.showCookiesAuth(result, headerHint, issueNameHint, isRequestHeader);
            reportPanel.show(result);
        });

        // Headers tab = the grouped Logger on top, the clicked request's Request/Response/etc.
        // detail underneath it, both in view at once (Burp Proxy History style). Cookies & Auth
        // tab is the same layout, its own inventory table (cookies + JWT/Basic/Bearer/API-key
        // tokens, see CookiePanel) and its own Detail panel underneath.
        JSplitPane headersWithDetail = new JSplitPane(JSplitPane.VERTICAL_SPLIT, loggerPanel, detailPanel);
        headersWithDetail.setResizeWeight(0.55);
        headersWithDetail.setDividerLocation(420);

        JSplitPane cookiesWithDetail = new JSplitPane(JSplitPane.VERTICAL_SPLIT, cookiePanel, cookieDetailPanel);
        cookiesWithDetail.setResizeWeight(0.55);
        cookiesWithDetail.setDividerLocation(420);

        tabs = new JTabbedPane();
        tabs.addTab("Headers",  headersWithDetail);
        tabs.addTab("Cookies & Auth", cookiesWithDetail);
        tabs.addTab("Rules",    rulesPanel);
        tabs.addTab("Settings", settingsPanel);
        updateReportTabVisibility(); // Report starts hidden unless already unlocked from a prior session
        installAutoActiveScanTabButton(tabs);

        // SettingsPanel is built once and kept alive for the whole session, not reconstructed per
        // view, so a setting changed elsewhere (e.g. the JWT active probe checkbox that also lives
        // in CookieAuthRulesDialog, same underlying QuimeraSettings field) would otherwise show
        // stale here until Burp restarts, and clicking Apply on some unrelated field would
        // silently revert it back. Re-sync every time Settings becomes the selected tab.
        tabs.addChangeListener(e -> {
            if (tabs.getSelectedComponent() == settingsPanel) settingsPanel.loadFromSettings();
        });

        statsLabel.setBorder(BorderFactory.createEmptyBorder(2, 8, 2, 8));
        statsLabel.setFont(statsLabel.getFont().deriveFont(Font.ITALIC, 11f));
        statsLabel.setForeground(Color.GRAY);
        updateStats();

        JPanel statusBar = new JPanel(new BorderLayout());
        statusBar.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, Color.LIGHT_GRAY));
        statusBar.add(buildLegend(), BorderLayout.WEST);
        statusBar.add(statsLabel,    BorderLayout.CENTER);

        root = new JPanel(new BorderLayout());
        root.add(tabs,      BorderLayout.CENTER);
        root.add(statusBar, BorderLayout.SOUTH);
    }

    /** Shows/hides the Report tab based on whether REPORT_TAB_UNLOCK is currently in the
     * suppressed-headers list, called once at startup (so an unlock from a previous session
     * survives a Burp restart, the list is persisted) and again every time Settings is applied. */
    private void updateReportTabVisibility() {
        boolean shouldShow = settings.getSuppressedHeaders().stream()
                .anyMatch(h -> h.equalsIgnoreCase(REPORT_TAB_UNLOCK));
        if (shouldShow == reportTabVisible) return;
        if (shouldShow) {
            int insertAt = Math.max(0, tabs.indexOfTab("Settings"));
            tabs.insertTab("Report", null, reportPanel, null, insertAt);
        } else {
            int idx = tabs.indexOfComponent(reportPanel);
            if (idx >= 0) tabs.removeTabAt(idx);
        }
        reportTabVisible = shouldShow;
    }

    /** One-click quick toggle for Settings > Auto Active Scan, docked at the far right of the same
     * row as the Headers/Cookies & Auth/Rules/Report/Settings tabs, not a separate bar, reachable
     * without opening Settings. Implemented as a dummy trailing tab whose tab-component is the
     * button itself, the same trick Swing apps use for an "x" close button inside a tab: the button
     * consumes its own click, so pressing it fires the toggle instead of switching pages, and the
     * change-listener guard below reverts selection if any Look and Feel ever lets the click fall
     * through to a real tab-switch. Both this button and the Settings-tab checkbox write straight
     * through to the shared QuimeraSettings and refresh each other's display on change, so
     * whichever one the user last touched, the other one shows the truth next time it's looked at. */
    private void installAutoActiveScanTabButton(JTabbedPane tabs) {
        autoActiveScanToggle.setFocusPainted(false);
        autoActiveScanToggle.setFont(autoActiveScanToggle.getFont().deriveFont(Font.BOLD, 11f));
        autoActiveScanToggle.addActionListener(e -> {
            settings.setAutoActiveScan(!settings.isAutoActiveScan());
            refreshAutoActiveScanToggle();
            settingsPanel.refreshAutoActiveScan();
        });
        refreshAutoActiveScanToggle();

        int buttonTabIndex = tabs.getTabCount();
        tabs.addTab(null, new JPanel()); // never shown as content, this tab is button-only
        tabs.setTabComponentAt(buttonTabIndex, autoActiveScanToggle);

        // The button tab's index used to be captured ONCE here and reused forever, which broke
        // the instant a tab got inserted/removed anywhere before it (the Report-tab easter egg:
        // unlocking it shifts every later index by one, so the stale captured index started
        // pointing at Settings instead of the button tab, every click on Settings then looked
        // like an accidental click on the button and got bounced straight back). Look the
        // button's CURRENT index up by its tab component instead, correct no matter how many
        // tabs get added/removed around it afterwards.
        int[] lastRealIndex = {0};
        tabs.addChangeListener(e -> {
            int currentButtonIndex = tabs.indexOfTabComponent(autoActiveScanToggle);
            if (tabs.getSelectedIndex() == currentButtonIndex) {
                tabs.setSelectedIndex(lastRealIndex[0]);
            } else {
                lastRealIndex[0] = tabs.getSelectedIndex();
            }
        });
    }

    private void refreshAutoActiveScanToggle() {
        boolean on = settings.isAutoActiveScan();
        autoActiveScanToggle.setText(on ? "Auto Active Scan: ON" : "Auto Active Scan: OFF");
        autoActiveScanToggle.setBackground(on ? new Color(46, 160, 90) : null);
        autoActiveScanToggle.setForeground(on ? Color.WHITE : null);
        autoActiveScanToggle.setOpaque(on);
        autoActiveScanToggle.setToolTipText(on
                ? "Auto Active Scan is ON: every new URL seen on intercepted proxy traffic gets probed "
                  + "automatically (CORS reflection, TRACE and HSTS). JWT forgery and session replay "
                  + "remain separate opt-ins. Click to turn off."
                : "Auto Active Scan is OFF: purely passive listening. Click to enable automatic active "
                  + "CORS/TRACE/HSTS probing for every new URL seen on intercepted proxy traffic.");
    }

    public String    caption()     { return TAB_NAME; }
    public Component uiComponent() { return root; }
    public void      shutdown()    { loggerPanel.shutdown(); }

    // ------ Public API (called by the HTTP handler, scanner, context menu, bulk analyzer) ---------------------------

    public void onResultAdded(UrlAnalysisResult result) {
        // Called from Burp's own HTTP-handling threads (not the EDT), the ConcurrentHashMap/
        // DomainData update is thread-safe and cheap to do here, but every Swing call below MUST
        // run on the EDT, and any exception in there must be visible (not silently swallowed),
        // or a real bug looks identical to "nothing is being captured".
        DomainData dd = domainStore.computeIfAbsent(result.host, DomainData::new);
        dd.addResult(result);
        // Note: retest status is deliberately NOT auto-reconciled from ordinary traffic here,
        // only the explicit "Retest Selected" action (DetailPanel/ReportPanel) re-verifies a
        // finding, and only by replaying the exact original request that detected it.

        SwingUtilities.invokeLater(() -> {
            try {
                if (settings.isRestrictToScope() && !isInScopeForView(result.url)) {
                    return; // Stored and analyzed; hidden only from Quimera's current UI view.
                }
                loggerPanel.addOrUpdateRow(result);
                cookiePanel.addOrUpdateRow(result);
                // Deliberately NOT refreshing the Detail/Report panels here even if they're
                // showing this same URL: once you click into a request its view should stay put,
                // not re-render (and reset scroll/highlight) every time background traffic for
                // that same path comes in. They only update on an explicit re-click or Retest.
                totalUrls = loggerPanel.rowCount();
                refreshVisibleStats();
                updateStats();
            } catch (Exception ex) {
                api.logging().logToError("[Quimera] UI update error in onResultAdded: " + ex);
            }
        });
    }

    public void focusResults(String host, String path) {
        loggerPanel.selectRow(host, path);
    }

    // ------ UI helpers ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

    private void onSettingsApplied() {
        updateReportTabVisibility();
        refreshScopeView();
    }

    /** Rebuilds only the visible tables. Captured results remain in domainStore regardless of
     * Target Scope, so changing this checkbox never suppresses analysis or loses evidence. */
    private void refreshScopeView() {
        List<UrlAnalysisResult> visible = new ArrayList<>();
        for (DomainData dd : domainStore.values()) {
            for (UrlAnalysisResult r : dd.getUrlResults().values()) {
                if (!settings.isRestrictToScope() || isInScopeForView(r.url)) visible.add(r);
            }
        }
        loggerPanel.clearAll();
        detailPanel.clearAll();
        cookiePanel.clearAll();
        cookieDetailPanel.clearAll();
        reportPanel.clearAll();
        for (UrlAnalysisResult r : visible) {
            loggerPanel.addOrUpdateRow(r);
            cookiePanel.addOrUpdateRow(r);
        }
        totalUrls = loggerPanel.rowCount();
        refreshVisibleStats();
        updateStats();
    }

    private void refreshVisibleStats() {
        List<UrlAnalysisResult> visible = domainStore.values().stream()
                .flatMap(dd -> dd.getUrlResults().values().stream())
                .filter(r -> !settings.isRestrictToScope() || isInScopeForView(r.url))
                .toList();
        totalFindings = visible.stream().mapToInt(r -> r.findings.size()).sum();
        totalHosts = (int) visible.stream().map(r -> r.host).distinct().count();
    }

    /** Scope is a presentation filter only. Burp may reject synthetic/browser URLs here; that
     * must never escape into result ingestion or erase already analyzed evidence. */
    private boolean isInScopeForView(String url) {
        try {
            return url != null && !url.isBlank() && api.scope().isInScope(url);
        } catch (RuntimeException ex) {
            api.logging().logToError("[Quimera] scope view ignored invalid URL: " + url);
            return false;
        }
    }

    private void clearAll() {
        domainStore.clear();
        retestTracker.clear();
        engine.clearSessionLifecycleState();
        sessionInvalidationProbe.clear();
        loggerPanel.clearAll();
        detailPanel.clearAll();
        cookiePanel.clearAll();
        cookieDetailPanel.clearAll();
        reportPanel.clearAll();
        totalUrls = 0;
        totalFindings = 0;
        totalHosts = 0;
        updateStats();
    }

    private void updateStats() {
        statsLabel.setText("  URLs: " + totalUrls + "  |  Findings: " + totalFindings +
                "  |  Hosts: " + totalHosts + "  ");
    }

    private JPanel buildLegend() {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        for (Severity s : Severity.values()) {
            JLabel b = new JLabel(" " + s.label + " ");
            b.setOpaque(true);
            b.setBackground(s.color);
            b.setForeground(Color.WHITE);
            b.setFont(b.getFont().deriveFont(Font.BOLD, 10f));
            b.setBorder(BorderFactory.createEmptyBorder(1, 5, 1, 5));
            p.add(b);
        }
        return p;
    }
}
