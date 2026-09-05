package com.b3xal.headeranalyzer.context;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import com.b3xal.headeranalyzer.analyzer.ActiveHeaderScanner;
import com.b3xal.headeranalyzer.analyzer.BulkAnalyzer;
import com.b3xal.headeranalyzer.analyzer.HeaderAnalysisEngine;
import com.b3xal.headeranalyzer.config.QuimeraSettings;
import com.b3xal.headeranalyzer.model.UrlAnalysisResult;
import com.b3xal.headeranalyzer.ui.QuimeraTab;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import com.b3xal.headeranalyzer.util.BackgroundExecutors;
import com.b3xal.headeranalyzer.util.SafeLogging;

/**
 * Right-click context menu, works from Proxy/Target selections AND message editors
 * (Repeater, Intruder, etc.), js-miner style: pick a request/response, right-click,
 * analyze with Quimera. Four items forming a single/bulk x passive/active matrix: "Analyze with
 * Quimera" (this exact request/response, no new traffic sent) and "Active header scan" (this one
 * endpoint, CORS/TRACE/HSTS, sends real probes) are the single-URL pair; "Analyze all <host> from
 * sitemap" and "Active scan all <host>" are their host-wide bulk equivalents.
 */
public class ContextMenuProvider implements ContextMenuItemsProvider {

    private final MontoyaApi api;
    private final HeaderAnalysisEngine engine;
    private final ActiveHeaderScanner activeScanner;
    private final BulkAnalyzer bulkAnalyzer;
    private final QuimeraSettings settings;
    private final QuimeraTab tab;
    private final ExecutorService executor = BackgroundExecutors.bounded("Quimera-Context", 4, 32);

    public ContextMenuProvider(MontoyaApi api,
                               HeaderAnalysisEngine engine,
                               ActiveHeaderScanner activeScanner,
                               BulkAnalyzer bulkAnalyzer,
                               QuimeraSettings settings,
                               QuimeraTab tab) {
        this.api           = api;
        this.engine        = engine;
        this.activeScanner = activeScanner;
        this.bulkAnalyzer  = bulkAnalyzer;
        this.settings      = settings;
        this.tab           = tab;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        // Support both proxy/target selections and message editors (Repeater, Intruder, etc.)
        List<HttpRequestResponse> selected = event.selectedRequestResponses();
        HttpRequestResponse representative = null;

        if (!selected.isEmpty()) {
            representative = selected.get(0);
        } else {
            Optional<MessageEditorHttpRequestResponse> editorRr = event.messageEditorRequestResponse();
            if (editorRr.isPresent()) {
                representative = editorRr.get().requestResponse();
            }
        }

        if (representative == null || representative.request() == null) return List.of();

        String url  = representative.request().url();
        String host = HeaderAnalysisEngine.extractHost(url);
        final List<HttpRequestResponse> toAnalyze = !selected.isEmpty() ? selected : List.of(representative);

        List<Component> items = new ArrayList<>();

        JMenuItem analyzeItem = new JMenuItem("Analyze with Quimera");
        analyzeItem.addActionListener(e -> analyzeSelected(toAnalyze));
        items.add(analyzeItem);

        HttpRequest activeTemplate = representative.request();
        JMenuItem activeItem = new JMenuItem("Active scan (CORS / TRACE / HSTS / WebDAV / Cache-key)");
        // Unlike analyzeSelected() below, this used to submit() with no try/catch at all: a
        // RejectedExecutionException from submit() itself (executor already shut down, e.g. a
        // stale menu item surviving an extension reload) or any exception inside runActiveProbe
        // vanished completely, no Errors tab entry, no Output line, nothing, indistinguishable
        // from the probe silently finding zero issues. Both are now logged.
        activeItem.addActionListener(e -> {
            try {
                executor.submit(() -> {
                    try {
                        runActiveProbe(url, activeTemplate);
                    } catch (Exception ex) {
                        SafeLogging.error(api, "[Quimera] Active scan probe error: " + ex.getMessage());
                    }
                });
            } catch (Exception ex) {
                SafeLogging.error(api, "[Quimera] Active scan could not be scheduled: " + ex.getMessage());
            }
        });
        items.add(activeItem);

        items.add(new JSeparator());

        JMenuItem sitemapItem = new JMenuItem("Analyze all " + host + " (sitemap)");
        sitemapItem.addActionListener(e -> analyzeFromSitemap(host));
        items.add(sitemapItem);

        JMenuItem activeAllItem = new JMenuItem("Active scan all " + host);
        activeAllItem.addActionListener(e -> activeScanHost(host));
        items.add(activeAllItem);

        return items;
    }

    public void shutdown() {
        executor.shutdownNow();
    }

    // ------ Single-request analysis (the EXACT selected request/response, no new traffic) ------------------------------

    private void analyzeSelected(List<HttpRequestResponse> requestResponses) {
        for (HttpRequestResponse rr : requestResponses) {
            executor.submit(() -> {
                try { analyzeOne(rr); }
                catch (Exception ex) { SafeLogging.error(api, "[Quimera] analyzeOne error: " + ex.getMessage()); }
            });
        }
    }

    private void analyzeOne(HttpRequestResponse existingRr) {
        try {
            if (existingRr.response() == null) return; // nothing captured yet (e.g. an unsent Repeater tab)
            String url = existingRr.request().url();
            if (HeaderAnalysisEngine.isOutOfBandProbeUrl(url)) return;

            UrlAnalysisResult result = toResult(url, existingRr);
            tab.onResultAdded(result);

            SwingUtilities.invokeLater(() -> tab.focusResults(result.host, result.path));

        } catch (Exception ex) {
            SafeLogging.error(api, "Quimera: analysis error: " + ex.getMessage());
        }
    }

    // ------ Single-endpoint active probe (CORS/TRACE/HSTS) ------------------------------------------------------------------------------

    private void runActiveProbe(String url, HttpRequest template) {
        if (settings.isContextMenuRequireScope() && !api.scope().isInScope(url)) {
            SwingUtilities.invokeLater(() ->
                    JOptionPane.showMessageDialog(
                            api.userInterface().swingUtils().suiteFrame(),
                            "URL is not in Burp scope:\n" + url, "Out of Scope", JOptionPane.WARNING_MESSAGE));
            return;
        }
        // Passing the real captured request lets the CORS battery replay it with only Origin
        // swapped (same cookies/auth) instead of a cookie-less synthetic probe, see
        // ActiveHeaderScanner#corsProbe.
        List<UrlAnalysisResult> results = activeScanner.scan(url, template);
        for (UrlAnalysisResult r : results) {
            tab.onResultAdded(r);
            com.b3xal.headeranalyzer.scanner.NativeProbeIssuePublisher.publish(api, r);
        }
        String host = HeaderAnalysisEngine.extractHost(url);
        SwingUtilities.invokeLater(() -> {
            tab.focusResults(host, null);
            SafeLogging.output(api, "[Quimera] Active header scan: " + results.size() + " probe(s) for " + url);
        });
    }

    // ------ Host-wide bulk actions ---------------------------------------------------------------------------------------------------------------------------------------------------------

    private void analyzeFromSitemap(String host) {
        bulkAnalyzer.analyzeSitemap(host,
                tab::onResultAdded,
                (done, total) -> {},
                () -> SwingUtilities.invokeLater(() -> {
                    tab.focusResults(host, null);
                    SafeLogging.output(api, "[Quimera] Sitemap analysis complete for " + host);
                }));
    }

    private void activeScanHost(String host) {
        int choice = JOptionPane.showConfirmDialog(
                api.userInterface().swingUtils().suiteFrame(),
                "This sends a fresh HTTP request (plus CORS/TRACE/HSTS/WebDAV probes) for every URL " +
                "Quimera has seen for " + host + ".\n\nContinue?",
                "Quimera: Active scan " + host,
                JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE);
        if (choice != JOptionPane.YES_OPTION) return;

        bulkAnalyzer.activeScanEntireTarget(host, settings.isContextMenuRequireScope(), true,
                r -> {
                    tab.onResultAdded(r);
                    com.b3xal.headeranalyzer.scanner.NativeProbeIssuePublisher.publish(api, r);
                },
                (done, total) -> {},
                () -> SwingUtilities.invokeLater(() -> {
                    tab.focusResults(host, null);
                    SafeLogging.output(api, "[Quimera] Active scan complete for " + host);
                }));
    }

    // ------ Helpers ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

    private UrlAnalysisResult toResult(String url, HttpRequestResponse response) {
        Map<String, String> headerMap = new LinkedHashMap<>();
        response.response().headers().forEach(h ->
                com.b3xal.headeranalyzer.util.HeaderMaps.addResponse(headerMap, h.name(), h.value()));

        Map<String, String> requestHeaderMap = new LinkedHashMap<>();
        response.request().headers().forEach(h ->
                com.b3xal.headeranalyzer.util.HeaderMaps.addRequest(requestHeaderMap, h.name(), h.value()));

        UrlAnalysisResult result = engine.analyze(url, headerMap, requestHeaderMap,
                response.response().statusCode(), response.response().bodyToString(), response.request().method(),
                true, response.request().bodyToString());
        try {
            result.rawRequest  = response.request().toString();
            result.rawResponse = response.response().toString();
        } catch (Exception ignored) {}
        result.method            = response.request().method();
        result.statusCode        = response.response().statusCode();
        result.contentLength     = response.response().body().length();
        result.originalRequest   = response.request();
        result.originalResponse  = response.response();
        return result;
    }
}
