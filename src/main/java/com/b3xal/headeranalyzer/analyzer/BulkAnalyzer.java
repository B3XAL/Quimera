package com.b3xal.headeranalyzer.analyzer;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.sitemap.SiteMapFilter;
import com.b3xal.headeranalyzer.config.QuimeraSettings;
import com.b3xal.headeranalyzer.model.UrlAnalysisResult;
import com.b3xal.headeranalyzer.util.BackgroundExecutors;

import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.function.Consumer;
import java.util.stream.Collectors;

/**
 * Shared bulk-analysis workflows, used by both the Logger's "Analyze" toolbar button and the
 * right-click context menu, so the two entry points behave identically instead of duplicating
 * sitemap/active-request logic:
 *
 *   - Passive re-analysis of everything Burp has already crawled (a host, or the entire target).
 *   - Active analysis: sends a fresh baseline request for every known URL, PLUS the
 *     {@link ActiveHeaderScanner} CORS/TRACE/HSTS probes on each one, "coger el target completo
 *     y analizar todo el target, incluso haciendo peticiones activas para las URLs que tenemos."
 *
 * All methods run on a small internal thread pool and report each result via a callback so the
 * caller can stream them into the Logger as they arrive, plus a final onDone callback.
 */
public class BulkAnalyzer {

    /** Reports (items completed, total items) so callers can render a determinate progress bar
     * instead of guessing at a percentage from the done-count alone. Total is only known once the
     * sitemap/URL list has been resolved, which happens inside the background task, so it can't be
     * handed to the caller up front, it comes through this same callback on every tick instead. */
    public interface ProgressListener {
        void onProgress(int done, int total);
    }

    private final MontoyaApi api;
    private final HeaderAnalysisEngine engine;
    private final ActiveHeaderScanner activeScanner;
    private final QuimeraSettings settings;
    private final ExecutorService executor = BackgroundExecutors.bounded("Quimera-Bulk", 4, 16);

    public BulkAnalyzer(MontoyaApi api, HeaderAnalysisEngine engine, ActiveHeaderScanner activeScanner,
                         QuimeraSettings settings) {
        this.api           = api;
        this.engine        = engine;
        this.activeScanner = activeScanner;
        this.settings      = settings;
    }

    public void shutdown() { executor.shutdownNow(); }

    // ── Passive: re-analyze already-crawled sitemap entries (no new requests) ──

    /** host == null means the entire target (whole sitemap). */
    public void analyzeSitemap(String host, Consumer<UrlAnalysisResult> onResult,
                                ProgressListener onProgress, Runnable onDone) {
        executor.submit(() -> {
            List<HttpRequestResponse> withResponse = sitemapEntries(host);
            int total = withResponse.size();
            int done = 0;
            for (HttpRequestResponse rr : withResponse) {
                try {
                    UrlAnalysisResult result = analyzeExisting(rr);
                    if (result != null) onResult.accept(result);
                } catch (Exception ex) {
                    api.logging().logToError("[Quimera] sitemap analysis error: " + ex.getMessage());
                }
                onProgress.onProgress(++done, total);
            }
            onDone.run();
        });
    }

    private UrlAnalysisResult analyzeExisting(HttpRequestResponse rr) {
        // sendRequest() can return a placeholder exchange after a timeout/connection failure.
        // A null response or status 0 is not an HTTP response and must not create a blank Logger
        // row populated with synthetic "Missing ..." findings.
        if (rr == null || rr.request() == null || rr.response() == null
                || rr.response().statusCode() < 100) return null;
        String url = rr.request().url();
        if (HeaderAnalysisEngine.isOutOfBandProbeUrl(url)) return null;
        Map<String, String> headerMap = collectHeaders(rr);
        // Same content-type/extension skip list QuimeraHttpHandler and HeaderPassiveScanner
        // already apply to live traffic (images/fonts/media/archives, no value analyzing security
        // headers on those), bulk "Analyze" used to ignore it entirely and process every sitemap
        // entry regardless of type, inconsistent with what a live scan of the same target reports.
        String contentType = headerMap.getOrDefault("Content-Type", headerMap.getOrDefault("content-type", ""));
        if (!settings.shouldAnalyze(contentType, url)) return null;
        UrlAnalysisResult result = engine.analyze(url, headerMap, collectRequestHeaders(rr),
                rr.response().statusCode(), rr.response().bodyToString(), rr.request().method(),
                true, rr.request().bodyToString());
        try {
            result.rawRequest  = rr.request().toString();
            result.rawResponse = rr.response().toString();
        } catch (Exception ignored) {}
        result.method           = rr.request().method();
        result.statusCode       = rr.response().statusCode();
        result.contentLength    = rr.response().body().length();
        result.originalRequest  = rr.request();
        result.originalResponse = rr.response();
        return result;
    }

    private List<HttpRequestResponse> sitemapEntries(String host) {
        List<HttpRequestResponse> items = new ArrayList<>();
        boolean restrictToScope;
        if (host == null || host.isBlank()) {
            items.addAll(api.siteMap().requestResponses());
            // "Entire target" is offered in the UI as "(Burp scope)" (AnalyzeDialog's scopeEntire
            // radio), so it must actually honour Burp's Target scope, api.siteMap() returns
            // everything Burp has ever seen a response for, in-scope or not (redirects to
            // third-party domains, CDN assets, etc.), unfiltered that silently reported/analyzed
            // out-of-scope requests even with "Entire target" selected.
            restrictToScope = true;
        } else {
            items.addAll(api.siteMap().requestResponses(SiteMapFilter.prefixFilter("https://" + host)));
            items.addAll(api.siteMap().requestResponses(SiteMapFilter.prefixFilter("http://"  + host)));
            // An explicit host was requested, honour it even if that host isn't in Burp's scope.
            restrictToScope = false;
        }
        return items.stream()
                .filter(rr -> rr.response() != null)
                .filter(rr -> !restrictToScope || api.scope().isInScope(rr.request().url()))
                .collect(Collectors.toList());
    }

    // ── Active: fresh requests (+ optional CORS/TRACE/HSTS probes) per URL ─────

    public void activeScanUrls(List<String> urls, boolean requireScope, boolean runProbes,
                                Consumer<UrlAnalysisResult> onResult,
                                ProgressListener onProgress, Runnable onDone) {
        activeScanUrls(urls, Map.of(), requireScope, runProbes, onResult, onProgress, onDone);
    }

    /** templates: URL -> the real captured request for it (cookies/headers included), if known.
     * When present for a given URL, the CORS Origin battery replays that exact request instead of
     * a cookie-less synthetic one, see {@link ActiveHeaderScanner#corsProbe}. Absent entries (e.g.
     * a manually-typed URL Quimera never captured) fall back to the synthetic probe as before. */
    public void activeScanUrls(List<String> urls, Map<String, HttpRequest> templates,
                                boolean requireScope, boolean runProbes,
                                Consumer<UrlAnalysisResult> onResult,
                                ProgressListener onProgress, Runnable onDone) {
        executor.submit(() -> {
            int total = urls.size();
            int done = 0;
            for (String url : urls) {
                try {
                    if (requireScope && !api.scope().isInScope(url)) {
                        onProgress.onProgress(++done, total);
                        continue;
                    }
                    HttpRequest freshRequest = HttpRequest.httpRequestFromUrl(url);
                    HttpRequestResponse rr = api.http().sendRequest(freshRequest);
                    UrlAnalysisResult baseline = analyzeExisting(rr);
                    if (baseline != null) onResult.accept(baseline);

                    if (runProbes) {
                        for (UrlAnalysisResult probeResult : activeScanner.scan(url, templates.get(url))) {
                            onResult.accept(probeResult);
                        }
                    }
                } catch (Exception ex) {
                    api.logging().logToError("[Quimera] active scan error for " + url + ": " + ex.getMessage());
                }
                onProgress.onProgress(++done, total);
            }
            onDone.run();
        });
    }

    /** host == null means the entire target: every URL Quimera has seen so far, deduped, keeping
     * the last-seen captured request per URL as the CORS battery's replay template. */
    public void activeScanEntireTarget(String host, boolean requireScope, boolean runProbes,
                                        Consumer<UrlAnalysisResult> onResult,
                                        ProgressListener onProgress, Runnable onDone) {
        executor.submit(() -> {
            Map<String, HttpRequest> templates = new LinkedHashMap<>();
            for (HttpRequestResponse rr : sitemapEntries(host)) {
                templates.put(rr.request().url(), rr.request());
            }
            List<String> urls = new ArrayList<>(templates.keySet());
            if (urls.isEmpty()) { onDone.run(); return; }
            activeScanUrls(urls, templates, requireScope, runProbes, onResult, onProgress, onDone);
        });
    }

    private static Map<String, String> collectHeaders(HttpRequestResponse rr) {
        Map<String, String> headerMap = new LinkedHashMap<>();
        rr.response().headers().forEach(h ->
                com.b3xal.headeranalyzer.util.HeaderMaps.addResponse(headerMap, h.name(), h.value()));
        return headerMap;
    }

    private static Map<String, String> collectRequestHeaders(HttpRequestResponse rr) {
        Map<String, String> headerMap = new LinkedHashMap<>();
        rr.request().headers().forEach(h ->
                com.b3xal.headeranalyzer.util.HeaderMaps.addRequest(headerMap, h.name(), h.value()));
        return headerMap;
    }
}
