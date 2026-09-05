package com.b3xal.headeranalyzer.proxy;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.b3xal.headeranalyzer.analyzer.ActiveHeaderScanner;
import com.b3xal.headeranalyzer.analyzer.HeaderAnalysisEngine;
import com.b3xal.headeranalyzer.analyzer.JwtActiveProbe;
import com.b3xal.headeranalyzer.analyzer.GoogleApiKeyProbe;
import com.b3xal.headeranalyzer.analyzer.SessionInvalidationProbe;
import com.b3xal.headeranalyzer.browser.ScopeHostTracker;
import com.b3xal.headeranalyzer.config.QuimeraSettings;
import com.b3xal.headeranalyzer.model.UrlAnalysisResult;
import com.b3xal.headeranalyzer.model.HeaderFinding;
import com.b3xal.headeranalyzer.model.Severity;
import com.b3xal.headeranalyzer.scanner.IssueFormatting;
import com.b3xal.headeranalyzer.scanner.NativeIssueDeduplicator;
import com.b3xal.headeranalyzer.scanner.NativeEvidenceMarker;
import com.b3xal.headeranalyzer.ui.QuimeraTab;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import com.b3xal.headeranalyzer.util.BackgroundExecutors;
import com.b3xal.headeranalyzer.util.SafeLogging;
import java.util.concurrent.atomic.AtomicBoolean;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue;

/**
 * Universal passive listener: registered via {@code api.http().registerHttpHandler(...)}, this
 * sees every HTTP response that passes through Burp's core, regardless of which tool sent it ,
 * Proxy, Repeater, Intruder, Scanner, Target replays, etc. Which tools actually feed analysis is
 * configurable in Settings (QuimeraSettings#getEnabledTools), all supported sources on by default.
 *
 * Passive header reading is unconditional. Active probing (CORS Origin battery, TRACE, HSTS
 * downgrade, see {@link ActiveHeaderScanner}) is governed by
 * {@link QuimeraSettings#isAutoActiveScan()} (on by default, independently removable in Settings);
 * when on, it runs asynchronously on
 * {@link #activeScanExecutor} so it never blocks Burp's response-received callback, and once per
 * distinct URL ({@link #autoScannedUrls}) so revisiting/reloading a page doesn't re-probe it.
 *
 * Separately, active JWT bypass testing (alg:none / bad-signature, see {@link JwtActiveProbe}) is
 * independently configurable via {@link QuimeraSettings#isJwtActiveProbeEnabled()} (on by default), keyed
 * on the token value itself ({@link #probedJwtTokens}) rather than the URL, so the same JWT seen
 * across many requests only ever gets forged and replayed once.
 *
 * A third, independently configurable probe, {@link SessionInvalidationProbe} via
 * {@link QuimeraSettings#isSessionInvalidationProbeEnabled()}: unlike the two probes above it
 * needs to see EVERY response (building its own recently-touched-path history), not just new
 * URLs/tokens, so it has no add-based dedup guard here, its own internal per-credential state
 * decides when a logout was actually detected and something is actually worth replaying.
 *
 * That statefulness is exactly why this one, alone among the three above it, is NOT fed EXTENSIONS-tagged
 * traffic ({@link QuimeraSettings#DEFAULT_ENABLED_TOOLS} includes it, and its own comment notes
 * re-processing Quimera's own probe requests there is normally harmless, true for the OTHER
 * passive/active checks, all idempotent overwrites of the same row). {@link SessionInvalidationProbe}
 * sends its own control/probe requests via its {@code ThrottledRequestSender}, which come back
 * through this same handler tagged EXTENSIONS; feeding those back into its evolving
 * lastValue/touch-history state is NOT idempotent, a probe request replaying an old Bearer token
 * looks, from the inside, exactly like "this host's token just changed again", corrupting the
 * history and risking a self-triggered false-positive finding. See the ToolType.EXTENSIONS guard
 * below.
 *
 * The cache-key disclosure probe ({@link ActiveHeaderScanner#scanCacheKey}) needs the same
 * ToolType.EXTENSIONS exclusion as {@link SessionInvalidationProbe}, for a different reason: every
 * attempt appends a unique cache-buster query parameter, so its own probe requests never collide
 * with {@link #cacheKeyScannedUrls}' add-based dedup the way the idempotent CORS/header battery's
 * repeat-the-same-URL requests do. Without the guard, a busted probe request comes back through
 * this handler tagged EXTENSIONS looking like a brand new, never-scanned URL with its own cache
 * evidence, which schedules another full probe, which sends more uniquely-busted sub-requests,
 * which schedule more probes again, an unbounded, self-amplifying loop instead of one bounded scan.
 *
 * A fourth, independently configurable probe, {@link GoogleApiKeyProbe} via
 * {@link QuimeraSettings#isGoogleApiKeyProbeEnabled()} (on by default): fires real read-only
 * requests against Google's own APIs using an exposed key found in an AUTH finding, once per
 * distinct key value ({@link #probedGoogleApiKeyFingerprints}), same "own control requests must
 * not feed back into passive analysis" guard via {@link GoogleApiKeyProbe#MARKER_HEADER}.
 */
public class QuimeraHttpHandler implements HttpHandler {

    private final MontoyaApi api;
    private final HeaderAnalysisEngine engine;
    private final QuimeraSettings settings;
    private final QuimeraTab tab;
    private final ActiveHeaderScanner activeScanner;
    private final JwtActiveProbe jwtActiveProbe;
    private final SessionInvalidationProbe sessionInvalidationProbe;
    private final GoogleApiKeyProbe googleApiKeyProbe;
    private final ScopeHostTracker scopeHostTracker;

    // Every response's own passive analysis (header-only for filtered/static content types, full
    // body-based analysis otherwise) runs here, never inline on this handler's own thread: it is
    // the highest-volume work in this class (every single response, not just auto-scanned URLs),
    // and running it synchronously measurably delayed ordinary page loads on asset-heavy sites,
    // confirmed live (a page that loaded instantly without Quimera visibly stalled with it
    // enabled). Separate from headerProbeExecutor (the active CORS/TRACE/HSTS/WebDAV battery) so
    // neither kind of work can starve the other.
    private final ExecutorService responseAnalysisExecutor = BackgroundExecutors.bounded("Quimera-Analysis", 4, 4096);
    // Credential/leak body scanning (CredentialBodyAnalyzer) is the single most CPU-expensive
    // check Quimera runs, ~25 regex signatures plus provider/context matching over the full
    // request+response body, and it runs on every JS/CSS response too, not just HTML. A single
    // thread deliberately caps it to one response at a time, so it can never compete for CPU with
    // the fast header/cookie/JWT analysis above (or with the browser/Burp itself) no matter how
    // much traffic is flowing; a queued asset just waits its turn a little longer instead.
    private final ExecutorService credentialScanExecutor = BackgroundExecutors.bounded("Quimera-Leaks", 1, 8192);
    // Keep high-volume per-URL CORS/header work isolated from credential validation. A busy page
    // can enqueue hundreds of resources; it must never starve or discard a discovered Google key.
    private final ExecutorService headerProbeExecutor = BackgroundExecutors.bounded("Quimera-Headers", 4, 256);
    // Cache-key coverage is latency-sensitive and cheap compared with the CORS battery. Keeping
    // it separate prevents a busy site from starving hundreds of URL-specific cache probes.
    private final ExecutorService cacheProbeExecutor = BackgroundExecutors.bounded("Quimera-CacheKey", 4, 2048);
    private final ExecutorService googleProbeExecutor = BackgroundExecutors.bounded("Quimera-Google", 2, 32);
    private final ExecutorService jwtProbeExecutor = BackgroundExecutors.bounded("Quimera-JWT", 2, 64);
    private final ExecutorService sessionProbeExecutor = BackgroundExecutors.bounded("Quimera-Session", 2, 256);
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private final Set<String> autoScannedUrls = ConcurrentHashMap.newKeySet();
    // Separate deduplication because cache-key diagnostics only run for URLs whose baseline has
    // demonstrated a real cache signal, while the general active battery has its own lifecycle.
    private final Set<String> cacheKeyScannedUrls = ConcurrentHashMap.newKeySet();
    // Once ANY response on a host shows real cache evidence, every other URL on that same host
    // becomes eligible too, even a specific response that itself carries no cache header (a MISS
    // on a backend that only stamps X-Cache on a HIT, a JS/CSS asset behind the same shared cache
    // as the HTML that showed the signal, etc.). Gating strictly per-response left real endpoints
    // on a confirmed-cached host completely unprobed just because that one exchange had no signal.
    private final Set<String> cacheConfirmedHosts = ConcurrentHashMap.newKeySet();
    // Keyed on the raw token string, not the URL: the same JWT gets re-sent on every request for
    // its whole lifetime (every page load, every asset fetch), probing it more than once would
    // just hammer the target with repeat forged-auth attempts for no new information.
    private final Set<String> probedJwtTokens = ConcurrentHashMap.newKeySet();
    private final Set<String> probedGoogleApiKeyFingerprints = ConcurrentHashMap.newKeySet();
    private static final Pattern GOOGLE_API_KEY = Pattern.compile("AIza[0-9A-Za-z_-]{35}");

    public QuimeraHttpHandler(MontoyaApi api, HeaderAnalysisEngine engine,
                               QuimeraSettings settings, QuimeraTab tab,
                               ActiveHeaderScanner activeScanner, JwtActiveProbe jwtActiveProbe,
                               SessionInvalidationProbe sessionInvalidationProbe,
                               ScopeHostTracker scopeHostTracker) {
        this.api      = api;
        this.engine   = engine;
        this.settings = settings;
        this.tab      = tab;
        this.activeScanner = activeScanner;
        this.jwtActiveProbe = jwtActiveProbe;
        this.sessionInvalidationProbe = sessionInvalidationProbe;
        this.googleApiKeyProbe = new GoogleApiKeyProbe(api);
        this.scopeHostTracker = scopeHostTracker;
    }

    /** Shuts down the background pool used for auto-active-scan probes. */
    public void shutdown() {
        closed.set(true);
        activeScanner.shutdown();
        jwtActiveProbe.shutdown();
        sessionInvalidationProbe.shutdown();
        googleApiKeyProbe.shutdown();
        responseAnalysisExecutor.shutdownNow();
        credentialScanExecutor.shutdownNow();
        headerProbeExecutor.shutdownNow();
        cacheProbeExecutor.shutdownNow();
        googleProbeExecutor.shutdownNow();
        jwtProbeExecutor.shutdownNow();
        sessionProbeExecutor.shutdownNow();
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        if (closed.get()) return RequestToBeSentAction.continueWith(requestToBeSent);
        scopeHostTracker.observe(requestToBeSent.url());
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        if (closed.get()) return ResponseReceivedAction.continueWith(responseReceived);
        try {
            String url = responseReceived.initiatingRequest().url();
            if (HeaderAnalysisEngine.isOutOfBandProbeUrl(url)
                    || HeaderAnalysisEngine.isQuimeraInternalUrl(url)) {
                return ResponseReceivedAction.continueWith(responseReceived);
            }
            var toolType = responseReceived.toolSource().toolType();

            if (!settings.isToolEnabled(toolType)) {
                return ResponseReceivedAction.continueWith(responseReceived);
            }

            // JwtActiveProbe's own control/forged-token requests (see MARKER_HEADER's own
            // javadoc): real Burp traffic, tagged EXTENSIONS same as anything else, but the token
            // they carry was never issued by the target, so the general passive pipeline below
            // must not independently re-analyze them (it was flagging JwtActiveProbe's fixed
            // garbage control token as a genuine "JWT has no expiration claim" finding, a false
            // positive about Quimera's own synthetic data). That class's own verdict on the
            // forged tokens still reaches the Logger, via its own separate, explicit call further
            // down. Two independent checks: the marker header, and (belt and suspenders, doesn't
            // depend on a custom header surviving anything) the fixed garbage token's own literal
            // value appearing in the request.
            if (responseReceived.initiatingRequest().hasHeader(JwtActiveProbe.MARKER_HEADER)
                    || responseReceived.initiatingRequest().hasHeader(GoogleApiKeyProbe.MARKER_HEADER)
                    || JwtActiveProbe.carriesGarbageToken(responseReceived.initiatingRequest())) {
                return ResponseReceivedAction.continueWith(responseReceived);
            }

            Map<String, String> headerMap = new LinkedHashMap<>();
            responseReceived.headers().forEach(h ->
                    com.b3xal.headeranalyzer.util.HeaderMaps.addResponse(headerMap, h.name(), h.value()));

            // Claim and schedule cache-key coverage BEFORE content-type/extension filtering.
            // Cache keys are URL-specific and can be exposed by HTML, API, image, font, download
            // or even error endpoints; the normal noise filters must not create blind spots here.
            boolean thisResponseHasCacheEvidence = ActiveHeaderScanner.hasCacheEvidence(headerMap);
            String cacheHost = HeaderAnalysisEngine.extractHost(url);
            if (thisResponseHasCacheEvidence && cacheHost != null && !cacheHost.isBlank()) {
                cacheConfirmedHosts.add(cacheHost);
            }
            // Host-level, not response-level: once ANY endpoint on this host proved it sits behind
            // a cache, every other URL on the same host is eligible too, not only the ones whose
            // own individual response happens to carry an explicit cache header.
            // toolType != EXTENSIONS: unlike the idempotent CORS/header battery below (which
            // safely re-runs on its own EXTENSIONS-tagged traffic because it always replays the
            // exact same URL), every cache-key attempt carries a unique cache-buster query
            // parameter, see the class javadoc. Without this guard the probe's own responses look
            // like brand new, never-scanned URLs and re-trigger themselves indefinitely.
            boolean cacheCandidate = settings.isAutoActiveScan()
                    && toolType != ToolType.EXTENSIONS
                    && (thisResponseHasCacheEvidence
                        || (cacheHost != null && cacheConfirmedHosts.contains(cacheHost)));
            boolean newCacheKeyUrl = cacheCandidate && cacheKeyScannedUrls.add(url);
            boolean newAutoUrl = settings.isAutoActiveScan() && autoScannedUrls.add(url);
            HttpRequest autoTemplate = responseReceived.initiatingRequest();
            // The real, un-probed exchange Quimera already captured for this URL, threaded through
            // so ActiveHeaderScanner's clean MISS->HIT confirmation has a genuine baseline
            // request/response to attach as evidence, not just its headers, see scan()'s javadoc.
            HttpRequestResponse autoBaseline = HttpRequestResponse.httpRequestResponse(autoTemplate, responseReceived);
            if (newCacheKeyUrl) {
                try {
                    cacheProbeExecutor.submit(() -> {
                        try {
                            if (closed.get()) return;
                            List<UrlAnalysisResult> cacheResults =
                                    activeScanner.scanCacheKey(url, autoTemplate, autoBaseline);
                            for (UrlAnalysisResult probeResult : cacheResults) {
                                if (closed.get()) return;
                                tab.onResultAdded(probeResult);
                                publishNativeProbeIssues(probeResult);
                            }
                        } catch (Exception ex) {
                            cacheKeyScannedUrls.remove(url);
                            SafeLogging.error(api, "[Quimera] cache-key probe error for " + url + ": " + ex.getMessage());
                        }
                    });
                } catch (java.util.concurrent.RejectedExecutionException rejected) {
                    cacheKeyScannedUrls.remove(url);
                    SafeLogging.error(api, "[Quimera] cache-key probe queue full; URL remains eligible: " + url);
                }
            }

            String contentType = headerMap.getOrDefault("Content-Type",
                                 headerMap.getOrDefault("content-type", ""));
            if (!settings.shouldAnalyze(contentType, url)) {
                // This filter exists to skip the EXPENSIVE body-based pipeline (credential
                // scanning, JS cookie/storage analysis, JWT/auth-header inspection) for static
                // assets, not to hide real header disclosures. engine.analyze(url, headers,
                // status, method) below is the cheap, header-only path, and applyContextFilter
                // already keeps EVERY Category.INFORMATION_DISCLOSURE (and COOKIE) finding
                // regardless of content type on purpose (see its own comment): a Server/
                // X-Backend-Server/X-Varnish-Ip/etc header leaks exactly as much on an image
                // response as on an HTML one. Gating the entire publish on "did a cache-key-
                // family finding fire" (the previous behaviour here) silently discarded that
                // already-correct result whenever the ONLY disclosure present was something else,
                // confirmed for real: X-Varnish-Ip/X-Varnish-Port (an internal backend IP:port)
                // on a plain .webp image never showed up, because no cache-key header happened to
                // be present on that same response.
                //
                try {
                    responseAnalysisExecutor.submit(() -> {
                        if (closed.get()) return;
                        UrlAnalysisResult headerOnly = engine.analyze(url, headerMap,
                                responseReceived.statusCode(), responseReceived.initiatingRequest().method())
                                .withExtraFindings(ActiveHeaderScanner.cacheKeyDisclosureFindings(headerMap));
                        if (headerOnly.findings.isEmpty()) return;
                        try {
                            headerOnly.rawRequest  = responseReceived.initiatingRequest().toString();
                            headerOnly.rawResponse = responseReceived.toString();
                        } catch (Exception ignored) {}
                        headerOnly.method           = responseReceived.initiatingRequest().method();
                        headerOnly.statusCode       = responseReceived.statusCode();
                        headerOnly.contentLength    = responseReceived.body().length();
                        headerOnly.originalRequest  = responseReceived.initiatingRequest();
                        headerOnly.originalResponse = responseReceived;
                        tab.onResultAdded(headerOnly);
                    });
                } catch (java.util.concurrent.RejectedExecutionException rejected) {
                    // A queue-full asset-analysis skip is not worth retrying or logging per URL,
                    // unlike the active-probe dedup guards above: there is no eligibility state to
                    // restore, this is a plain miss, not a scan that silently never happened.
                }
                return ResponseReceivedAction.continueWith(responseReceived);
            }

            // The full body-based pipeline (credential scanning, JS cookie/storage analysis, JWT/
            // auth-header inspection, plus every probe it can trigger below) is the most expensive
            // work in this class. It used to run right here, inline, before this method returned,
            // which measurably delayed the browser getting the HTML/API response it was actually
            // waiting on (confirmed live). Scheduled on responseAnalysisExecutor instead so nothing
            // Quimera does can ever be in the way of ordinary browsing/proxy use.
            try {
                responseAnalysisExecutor.submit(() -> {
                    if (closed.get()) return;
                    runResponseAnalysis(url, headerMap, responseReceived, toolType, newAutoUrl);
                });
            } catch (java.util.concurrent.RejectedExecutionException rejected) {
                if (newAutoUrl) autoScannedUrls.remove(url); // restore eligibility for a later retry
                SafeLogging.error(api, "[Quimera] response analysis queue full; URL remains eligible: " + url);
            }

        } catch (Exception ex) {
            // Never interrupt live traffic because of an analysis error, but do surface it ,
            // silently swallowing this made past failures indistinguishable from "nothing to report".
            SafeLogging.error(api, "[Quimera] passive capture error: " + ex);
        }

        return ResponseReceivedAction.continueWith(responseReceived);
    }

    /** The full per-response passive analysis and every probe it can trigger (Google key
     * verification, the non-cache active battery, JWT active probe, session invalidation), always
     * run on {@link #responseAnalysisExecutor}, never on the HTTP handler's own thread, see the
     * call site's comment. Exceptions are caught here, not by the caller: by the time this runs,
     * {@code handleHttpResponseReceived} has already returned on a different thread. */
    private void runResponseAnalysis(String url, Map<String, String> headerMap,
                                      HttpResponseReceived responseReceived, ToolType toolType,
                                      boolean newAutoUrl) {
        try {
            // Request headers too (Authorization/Cookie/API-key headers), so AuthHeaderAnalyzer can
            // recognize JWT/Basic-Auth/Bearer/API-key tokens, those live in the request, not here.
            Map<String, String> requestHeaderMap = new LinkedHashMap<>();
            responseReceived.initiatingRequest().headers().forEach(h ->
                    com.b3xal.headeranalyzer.util.HeaderMaps.addRequest(requestHeaderMap, h.name(), h.value()));
            boolean cookiesAuthSource = settings.isCookiesAuthToolEnabled(toolType);

            UrlAnalysisResult result = engine.analyze(url, headerMap, requestHeaderMap,
                    responseReceived.statusCode(), responseReceived.bodyToString(),
                    responseReceived.initiatingRequest().method(), cookiesAuthSource,
                    responseReceived.initiatingRequest().bodyToString());

            try {
                result.rawRequest  = responseReceived.initiatingRequest().toString();
                result.rawResponse = responseReceived.toString();
            } catch (Exception ignored) {}
            result.method          = responseReceived.initiatingRequest().method();
            result.statusCode      = responseReceived.statusCode();
            result.contentLength   = responseReceived.body().length();
            result.originalRequest  = responseReceived.initiatingRequest();
            result.originalResponse = responseReceived;

            tab.onResultAdded(result);

            // Request/auth body analysis is intentionally source-aware: unlike Burp's passive
            // scan callback, this listener knows which tool produced the exchange. Publish only
            // actionable AUTH findings from sources enabled in Cookies & Auth, preserving the
            // default Proxy/Repeater/Discovery noise boundary. INFORMATION stays in Quimera.
            if (cookiesAuthSource) {
                HttpRequestResponse evidence = HttpRequestResponse.httpRequestResponse(
                        responseReceived.initiatingRequest(), responseReceived);
                publishNativeAuthIssues(result, evidence);
            }

            if (cookiesAuthSource && settings.isGoogleApiKeyProbeEnabled()) {
                HttpRequestResponse sourceEvidence = HttpRequestResponse.httpRequestResponse(
                        responseReceived.initiatingRequest(), responseReceived);
                scanForGoogleApiKeys(result, sourceEvidence);
            }

            // Credential/leak body scanning is deliberately NOT part of the `result` above, see
            // HeaderAnalysisEngine.analyzeCredentialBodies' own comment: it is by far the most
            // CPU-expensive check in this pipeline, and runs on every JS/CSS response too, not
            // just HTML. Submitted to its own single-threaded queue so it can never compete for
            // CPU with the fast analysis above; whenever it completes (a little behind live
            // traffic on a busy site is expected and fine), its findings are merged into the SAME
            // Logger row via UrlAnalysisResult#withExtraFindings (rowKey() does not depend on
            // findings, only path/method/probeLabel, all unchanged here), not a separate row.
            if (cookiesAuthSource) {
                String bodyForCreds = responseReceived.bodyToString();
                String requestBodyForCreds = responseReceived.initiatingRequest().bodyToString();
                try {
                    credentialScanExecutor.submit(() -> {
                        if (closed.get()) return;
                        List<HeaderFinding> credFindings = engine.analyzeCredentialBodies(
                                url, headerMap, requestHeaderMap, bodyForCreds, requestBodyForCreds);
                        if (credFindings.isEmpty()) return;
                        UrlAnalysisResult withCreds = result.withExtraFindings(credFindings);
                        tab.onResultAdded(withCreds);
                        HttpRequestResponse credEvidence = HttpRequestResponse.httpRequestResponse(
                                responseReceived.initiatingRequest(), responseReceived);
                        publishNativeAuthIssues(withCreds, credEvidence);
                        if (settings.isGoogleApiKeyProbeEnabled()) scanForGoogleApiKeys(withCreds, credEvidence);
                    });
                } catch (java.util.concurrent.RejectedExecutionException rejected) {
                    SafeLogging.error(api, "[Quimera] leak-scan queue full; skipping body credential scan for " + url);
                }
            }

            if (newAutoUrl) {
                HttpRequest template = responseReceived.initiatingRequest();
                try {
                    headerProbeExecutor.submit(() -> {
                        try {
                            if (closed.get()) return;
                            int count = 0;
                            for (UrlAnalysisResult probeResult : activeScanner.scanNonCacheProbes(url, template)) {
                                if (closed.get()) return;
                                tab.onResultAdded(probeResult);
                                publishNativeProbeIssues(probeResult);
                                count++;
                            }
                            // Previously silent on the success path (0 or more probes), which made
                            // "auto active scan ran and found nothing" indistinguishable from "auto
                            // active scan never ran at all" in Output/Errors. Always log the count.
                            SafeLogging.output(api, "[Quimera] auto active scan: " + count + " probe(s) for " + url);
                        } catch (Exception ex) {
                            SafeLogging.error(api, "[Quimera] auto active scan error for " + url + ": " + ex.getMessage());
                        }
                    });
                } catch (java.util.concurrent.RejectedExecutionException rejected) {
                    // Do not poison dedup on a transient queue-full condition: a URL that never
                    // actually got probed must remain eligible for a later retry, same as the
                    // cache-key queue's own rejection handler just above does.
                    autoScannedUrls.remove(url);
                    SafeLogging.error(api, "[Quimera] non-cache active-probe queue full; URL remains eligible: " + url);
                }
            }
            // No log line for the "already scanned this session" skip: a busy/dynamic site can
            // re-request the same URL hundreds of times in a session, and the one-time success log
            // above already tells the analyst this URL WAS probed, logging every later dedup hit
            // added nothing but Output-tab noise proportional to traffic volume, not to anything
            // Quimera actually did.

            if (cookiesAuthSource && settings.isJwtActiveProbeEnabled()) {
                HttpRequest template = responseReceived.initiatingRequest();
                for (JwtActiveProbe.TokenLocation loc : JwtActiveProbe.locate(template)) {
                    if (!probedJwtTokens.add(loc.token())) continue; // already probed this exact token
                    try {
                        jwtProbeExecutor.submit(() -> {
                            try {
                                if (closed.get()) return;
                                UrlAnalysisResult probeResult = jwtActiveProbe.probe(url, template, responseReceived, loc);
                                if (!closed.get() && probeResult != null) tab.onResultAdded(probeResult);
                            } catch (Exception ex) {
                                SafeLogging.error(api, "[Quimera] JWT active probe error for " + url + ": " + ex.getMessage());
                            }
                        });
                    } catch (java.util.concurrent.RejectedExecutionException rejected) {
                        probedJwtTokens.remove(loc.token());
                    }
                }
            }

            // Session invalidation probe (SessionInvalidationProbe): unlike the two probes above,
            // this needs to see EVERY response regardless of whether it turns out to fire anything
            // (it's building the recently-touched-path history a logout, whenever it happens,
            // replays against), not just once per distinct URL/token, so there's no add-based
            // dedup guard here, the class's own internal state/latches handle that instead.
            //
            // toolType != EXTENSIONS: this class's own control/probe requests (safeSend ->
            // api.http().sendRequest) come back through this exact handler tagged EXTENSIONS.
            // Feeding those back into its own evolving per-host token/cookie history would look
            // like a genuine new touch (or worse, an old-token-came-back "token change"), see the
            // class javadoc above, so its own traffic is excluded here specifically.
            if (cookiesAuthSource && settings.isSessionInvalidationProbeEnabled()
                    && toolType != ToolType.EXTENSIONS) {
                String host = HeaderAnalysisEngine.extractHost(url);
                HttpRequestResponse rr = HttpRequestResponse.httpRequestResponse(
                        responseReceived.initiatingRequest(), responseReceived);
                var cookiesAndAuthConfig = settings.cookiesAndAuthConfig();
                try {
                    sessionProbeExecutor.submit(() -> {
                    try {
                        if (closed.get()) return;
                        for (UrlAnalysisResult probeResult : sessionInvalidationProbe.observe(host, rr, cookiesAndAuthConfig)) {
                            if (closed.get()) return;
                            tab.onResultAdded(probeResult);
                        }
                    } catch (Exception ex) {
                        SafeLogging.error(api, "[Quimera] session invalidation probe error for " + url + ": " + ex.getMessage());
                    }
                    });
                } catch (java.util.concurrent.RejectedExecutionException ignored) {
                    // Session history is opportunistic; never break passive capture under load.
                }
            }
        } catch (Exception ex) {
            // Never interrupt live traffic because of an analysis error, but do surface it,
            // silently swallowing this made past failures indistinguishable from "nothing to report".
            SafeLogging.error(api, "[Quimera] passive capture error: " + ex);
        }
    }

    /** Scans an already-produced result's AUTH findings for an exposed Google API key and fires
     * {@link GoogleApiKeyProbe} for each new one found, deduplicated globally by key fingerprint.
     * Shared between the fast per-response result and the (later, separately-queued) leak-scan
     * follow-up, so a Google key found deep in a JS body via {@code analyzeCredentialBodies} gets
     * the exact same verification treatment as one found in a header. */
    private void scanForGoogleApiKeys(UrlAnalysisResult result, HttpRequestResponse sourceEvidence) {
        for (HeaderFinding finding : result.findings) {
            if (finding.category != HeaderFinding.Category.AUTH) continue;
            String searchable = (finding.headerValue == null ? "" : finding.headerValue) + " "
                    + (finding.evidence == null ? "" : finding.evidence);
            Matcher matcher = GOOGLE_API_KEY.matcher(searchable);
            while (matcher.find()) {
                String key = matcher.group();
                String sourceLocation = finding.headerName;
                String keyFingerprint = fingerprint(key);
                if (!probedGoogleApiKeyFingerprints.add(keyFingerprint)) continue;
                try {
                    googleProbeExecutor.submit(() -> {
                        if (closed.get()) return;
                        UrlAnalysisResult probeResult = googleApiKeyProbe.probe(
                                key, result, sourceLocation, sourceEvidence);
                        if (closed.get() || probeResult == null) return;
                        tab.onResultAdded(probeResult);
                        publishNativeAuthIssues(probeResult, sourceEvidence);
                    });
                } catch (java.util.concurrent.RejectedExecutionException rejected) {
                    // Do not poison deduplication: a later sighting must be able to retry.
                    probedGoogleApiKeyFingerprints.remove(keyFingerprint);
                    SafeLogging.error(api, "[Quimera] Google API key probe queue is busy; " +
                            "the key remains eligible for retry.");
                }
            }
        }
    }

    private void publishNativeAuthIssues(UrlAnalysisResult result, HttpRequestResponse evidence) {
        String host = HeaderAnalysisEngine.extractHost(result.url);
        for (HeaderFinding finding : result.findings) {
            String nativeTitle = IssueFormatting.nativeTitle(finding);
            if (finding.category != HeaderFinding.Category.AUTH
                    || finding.severity == Severity.INFORMATION
                    || !NativeIssueDeduplicator.first(host, nativeTitle)) continue;
            try {
                List<HttpRequestResponse> issueEvidence = result.probeExchanges.isEmpty()
                        ? List.of(NativeEvidenceMarker.mark(evidence, finding))
                        : result.probeExchanges.stream()
                                .map(rr -> NativeEvidenceMarker.mark(rr, finding)).toList();
                api.siteMap().add(auditIssue(
                        nativeTitle, IssueFormatting.buildDetail(finding, IssueFormatting.SOURCE_COOKIES_AUTH),
                        IssueFormatting.buildRemediation(finding), result.url,
                        finding.severity.burpSeverity, finding.confidence.burpConfidence,
                        "Detected by Quimera from an enabled Cookies & Auth traffic source.",
                        null, finding.severity.burpSeverity, issueEvidence));
            } catch (Exception ex) {
                SafeLogging.error(api, "[Quimera] native auth issue error: " + ex.getMessage());
            }
        }
    }

    private void publishNativeProbeIssues(UrlAnalysisResult result) {
        com.b3xal.headeranalyzer.scanner.NativeProbeIssuePublisher.publish(api, result);
    }

    private static String fingerprint(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8));
            return java.util.HexFormat.of().formatHex(digest);
        } catch (Exception impossible) {
            return Integer.toHexString(value.hashCode());
        }
    }
}
