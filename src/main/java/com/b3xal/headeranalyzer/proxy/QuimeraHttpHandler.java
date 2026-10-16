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
import com.b3xal.headeranalyzer.analyzer.HeaderInfluenceProbe;
import com.b3xal.headeranalyzer.analyzer.SessionInvalidationProbe;
import com.b3xal.headeranalyzer.browser.ScopeHostTracker;
import com.b3xal.headeranalyzer.config.QuimeraSettings;
import com.b3xal.headeranalyzer.model.UrlAnalysisResult;
import com.b3xal.headeranalyzer.model.HeaderFinding;
import com.b3xal.headeranalyzer.model.Severity;
import com.b3xal.headeranalyzer.scanner.IssueFormatting;
import com.b3xal.headeranalyzer.scanner.NativeIssueDeduplicator;
import com.b3xal.headeranalyzer.scanner.NativeEvidenceMarker;
import com.b3xal.headeranalyzer.scanner.NativeAuthIssuePublisher;
import com.b3xal.headeranalyzer.ui.QuimeraTab;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.PriorityBlockingQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import com.b3xal.headeranalyzer.util.BackgroundExecutors;
import com.b3xal.headeranalyzer.util.SafeLogging;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.nio.charset.StandardCharsets;
import java.net.URI;
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
    private final HeaderInfluenceProbe headerInfluenceProbe;
    private final ScopeHostTracker scopeHostTracker;

    // Every response's own passive analysis (header-only for filtered/static content types, full
    // body-based analysis otherwise) runs here, never inline on this handler's own thread: it is
    // the highest-volume work in this class (every single response, not just auto-scanned URLs),
    // and running it synchronously measurably delayed ordinary page loads on asset-heavy sites,
    // confirmed live (a page that loaded instantly without Quimera visibly stalled with it
    // enabled). Separate from headerProbeExecutor (the active CORS/TRACE/HSTS/WebDAV battery) so
    // neither kind of work can starve the other.
    private final ThreadPoolExecutor responseAnalysisExecutor = responseAnalysisExecutor();
    private final AtomicLong responseAnalysisSequence = new AtomicLong();
    // Credential/leak body scanning (CredentialBodyAnalyzer) is the single most CPU-expensive
    // check Quimera runs, ~25 regex signatures plus provider/context matching over the full
    // request+response body, and it runs on every JS/CSS response too, not just HTML. One
    // worker deliberately serializes it, so it can never compete for CPU with
    // the fast header/cookie/JWT analysis above (or with the browser/Burp itself) no matter how
    // much traffic is flowing. Repeater/Intruder are analyst-initiated work, so they are placed
    // ahead of a passive asset backlog in that same one-worker lane; this does not add requests
    // or bypass the normal scope/tool gates.
    private final ThreadPoolExecutor credentialScanExecutor = credentialScanExecutor();
    private final AtomicLong credentialScanSequence = new AtomicLong();
    // Keep high-volume per-URL CORS/header work isolated from credential validation. A busy page
    // can enqueue hundreds of resources; it must never starve or discard a discovered Google key.
    private final ExecutorService headerProbeExecutor = BackgroundExecutors.lossless("Quimera-Headers", 1);
    // Cache-key coverage is latency-sensitive and cheap compared with the CORS battery. Keeping
    // it separate prevents a busy site from starving hundreds of URL-specific cache probes.
    private final ExecutorService cacheProbeExecutor = BackgroundExecutors.lossless("Quimera-CacheKey", 1);
    private final ExecutorService googleProbeExecutor = BackgroundExecutors.lossless("Quimera-Google", 2);
    private final ExecutorService jwtProbeExecutor = BackgroundExecutors.lossless("Quimera-JWT", 2);
    private final ExecutorService sessionProbeExecutor = BackgroundExecutors.lossless("Quimera-Session", 2);
    private final ExecutorService headerInfluenceExecutor = BackgroundExecutors.lossless("Quimera-HeaderInfluence", 1);
    // Fixed session cap avoids retaining unbounded URLs/auth contexts on long browsing sessions.
    private final Set<String> headerInfluenceContexts = ConcurrentHashMap.newKeySet();
    private static final int MAX_HEADER_INFLUENCE_CONTEXTS = 10_000;
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
    // A cache signal is host-wide, but automatic diagnostic coverage must not turn that into an
    // unbounded scan of every image, route variant and scanner-generated path on the host.
    private final Map<String, AtomicInteger> autoCacheProbeCounts = new ConcurrentHashMap<>();
    private static final int MAX_AUTO_CACHE_PROBES_PER_HOST = 8;
    private static final Pattern AWS_ACCESS_KEY_CANDIDATE = Pattern.compile("(?<![A-Z0-9])AKIA[A-Z0-9]{16}(?![A-Z0-9])");
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
        this.headerInfluenceProbe = activeScanner.headerInfluenceProbe();
        this.scopeHostTracker = scopeHostTracker;
    }

    /** Shuts down the background pool used for auto-active-scan probes. */
    public void shutdown() {
        closed.set(true);
        // Burp can dispose logging before its queued extension tasks finish unwinding. Prevent
        // those tasks from making an already-disposed logger emit an internal Burp NPE.
        SafeLogging.disable();
        activeScanner.shutdown();
        jwtActiveProbe.shutdown();
        sessionInvalidationProbe.shutdown();
        googleApiKeyProbe.shutdown();
        headerInfluenceProbe.shutdown();
        headerInfluenceExecutor.shutdownNow();
        headerInfluenceContexts.clear();
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
            // Scope is an execution boundary, not merely a UI filter.  This happens before body
            // extraction, persistence and every automatic probe, so a tracker/CDN outside the
            // project cannot consume Quimera workers just because the proxied page referenced it.
            if (settings.isRestrictToScope() && !isInScopeSafely(url)) {
                return ResponseReceivedAction.continueWith(responseReceived);
            }

            // Quimera's own probe traffic is tagged EXTENSIONS. Do not feed its synthetic
            // request-side controls back into the passive pipeline, but never let a copied marker
            // suppress an analyst's explicit Repeater/Intruder replay: that replay can produce a
            // real server-side disclosure in its response and must be analyzed.
            if (toolType == ToolType.EXTENSIONS && (
                    responseReceived.initiatingRequest().hasHeader(com.b3xal.headeranalyzer.util.ThrottledRequestSender.MARKER_HEADER)
                || responseReceived.initiatingRequest().hasHeader(JwtActiveProbe.MARKER_HEADER)
                    || responseReceived.initiatingRequest().hasHeader(GoogleApiKeyProbe.MARKER_HEADER)
                    || responseReceived.initiatingRequest().hasHeader(HeaderInfluenceProbe.MARKER_HEADER)
                    || JwtActiveProbe.carriesGarbageToken(responseReceived.initiatingRequest()))) {
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
            boolean automaticProbeEligible = settings.isAutoActiveScan()
                    && isInScopeSafely(url)
                    && isAutomaticProbeSource(toolType)
                    && isAutomaticProbeCandidate(url, responseReceived.initiatingRequest().method(),
                    responseReceived.statusCode(), contentType(headerMap));
            boolean cacheCandidate = automaticProbeEligible
                    && (thisResponseHasCacheEvidence
                    || (cacheHost != null && cacheConfirmedHosts.contains(cacheHost)));
            boolean newCacheKeyUrl = cacheCandidate && cacheKeyScannedUrls.add(url)
                    && claimAutoCacheProbe(cacheHost);
            boolean newAutoUrl = automaticProbeEligible && autoScannedUrls.add(url);
            HttpRequest autoTemplate = responseReceived.initiatingRequest();
            // The real, un-probed exchange Quimera already captured for this URL, threaded through
            // so ActiveHeaderScanner's clean MISS->HIT confirmation has a genuine baseline
            // request/response to attach as evidence, not just its headers, see scan()'s javadoc.
            // Queued active work can outlive this HttpHandler callback.  Move its messages to
            // Burp-managed temporary storage before handing them to a background lane; retaining
            // the callback objects themselves is specifically unsafe on large BApp projects.
            HttpRequestResponse autoBaseline = automaticProbeEligible
                    ? HttpRequestResponse.httpRequestResponse(autoTemplate, responseReceived).copyToTempFile()
                    : null;
            if (autoBaseline != null && settings.isHeaderInfluenceProbeEnabled()
                    && HeaderInfluenceProbe.eligible(autoBaseline)) {
                scheduleHeaderInfluence(autoBaseline);
            }
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
                            SafeLogging.error(api, "[Quimera] cache-key probe error for " + url + ": " + ex.getMessage());
                        }
                    });
                } catch (java.util.concurrent.RejectedExecutionException rejected) {
                    cacheKeyScannedUrls.remove(url);
                    releaseAutoCacheProbe(cacheHost);
                    SafeLogging.error(api, "[Quimera] cache-key probe was not accepted; URL remains eligible: " + url);
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
                    HttpRequestResponse queuedExchange = HttpRequestResponse
                            .httpRequestResponse(responseReceived.initiatingRequest(), responseReceived).copyToTempFile();
                    submitResponseAnalysis(toolType, () -> {
                        if (closed.get()) return;
                        try {
                            Map<String,String> assetRequest = new LinkedHashMap<>();
                            queuedExchange.request().headers().forEach(h ->
                                    com.b3xal.headeranalyzer.util.HeaderMaps.addRequest(assetRequest,h.name(),h.value()));
                            UrlAnalysisResult headerOnly = engine.analyzeResponseHeaders(url, headerMap, assetRequest,
                                    queuedExchange.response().statusCode(), queuedExchange.response().bodyToString(), queuedExchange.request().method())
                                    .withExtraFindings(ActiveHeaderScanner.cacheKeyDisclosureFindings(headerMap));
                            // MIME/extension filtering only suppresses analyses that make no sense
                            // for binary assets. A credential can still be exposed in a source map,
                            // downloadable configuration or mislabelled response, so body leak
                            // detection always runs for every in-scope captured response.
                            List<HeaderFinding> credFindings = engine.analyzeCredentialBodies(url, headerMap,
                                    assetRequest, queuedExchange.response().bodyToString(),
                                    queuedExchange.request().bodyToString());
                            if (!credFindings.isEmpty()) headerOnly = headerOnly.withExtraFindings(credFindings);
                            if (headerOnly.findings.isEmpty()) return;
                            try {
                                headerOnly.rawRequest  = queuedExchange.request().toString();
                                headerOnly.rawResponse = queuedExchange.response().toString();
                            } catch (Exception ignored) {}
                            headerOnly.method           = queuedExchange.request().method();
                            headerOnly.statusCode       = queuedExchange.response().statusCode();
                            headerOnly.contentLength    = queuedExchange.response().body().length();
                            headerOnly.originalRequest  = queuedExchange.request();
                            headerOnly.originalResponse = queuedExchange.response();
                            tab.onResultAdded(headerOnly);
                            publishNativeAuthIssues(headerOnly, queuedExchange);
                        } catch (Exception ex) {
                            // ExecutorService.submit() retains task failures in its Future; without
                            // this boundary an asset-analysis failure would be invisible to Burp.
                            SafeLogging.error(api, "[Quimera] asset response analysis error for " + url + ": " + ex);
                        }
                    });
                } catch (java.util.concurrent.RejectedExecutionException rejected) {
                    // This unbounded lane only rejects after shutdown, never because normal
                    // traffic filled a queue.  Still make a dropped capture explicit.
                    SafeLogging.error(api, "[Quimera] asset response analysis unavailable during shutdown: " + url);
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
                HttpRequestResponse queuedExchange = HttpRequestResponse
                        .httpRequestResponse(responseReceived.initiatingRequest(), responseReceived).copyToTempFile();
                submitResponseAnalysis(toolType, () -> {
                    if (closed.get()) return;
                    runResponseAnalysis(url, headerMap, queuedExchange, toolType, newAutoUrl, automaticProbeEligible);
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
                                      HttpRequestResponse responseReceived, ToolType toolType,
                                      boolean newAutoUrl, boolean automaticProbeEligible) {
        try {
            // Request headers too (Authorization/Cookie/API-key headers), so AuthHeaderAnalyzer can
            // recognize JWT/Basic-Auth/Bearer/API-key tokens, those live in the request, not here.
            Map<String, String> requestHeaderMap = new LinkedHashMap<>();
            responseReceived.request().headers().forEach(h ->
                    com.b3xal.headeranalyzer.util.HeaderMaps.addRequest(requestHeaderMap, h.name(), h.value()));
            boolean cookiesAuthSource = settings.isCookiesAuthToolEnabled(toolType);
            // An analyst explicitly sent Repeater/Intruder traffic to inspect its outcome. Run
            // the body-leak pass in this already-background, priority response task so its result
            // is created and published atomically with the response, rather than relying on a
            // later queue/UI merge that can be overtaken by another result for the same URL.
            // This is still never on Burp's HTTP callback and remains capped by the two response
            // workers; it sends no additional requests.
            boolean interactiveSource = toolType == ToolType.REPEATER || toolType == ToolType.INTRUDER;

            UrlAnalysisResult result = engine.analyze(url, headerMap, requestHeaderMap,
                    responseReceived.response().statusCode(), responseReceived.response().bodyToString(),
                    responseReceived.request().method(), cookiesAuthSource,
                    responseReceived.request().bodyToString());
            List<HeaderFinding> interactiveCredentialFindings = List.of();
            if (interactiveSource) {
                interactiveCredentialFindings = engine.analyzeCredentialBodies(url, headerMap, requestHeaderMap,
                        responseReceived.response().bodyToString(), responseReceived.request().bodyToString());
                boolean awsCandidate = AWS_ACCESS_KEY_CANDIDATE.matcher(responseReceived.response().bodyToString()).find();
                if (awsCandidate && interactiveCredentialFindings.isEmpty()) {
                    SafeLogging.error(api, "[Quimera] credential-shaped content in " + toolType.toolName()
                            + " response produced no leak finding: " + url);
                }
                if (!interactiveCredentialFindings.isEmpty()) {
                    result = result.withExtraFindings(interactiveCredentialFindings);
                }
            }

            try {
                result.rawRequest  = responseReceived.request().toString();
                result.rawResponse = responseReceived.response().toString();
            } catch (Exception ignored) {}
            result.method          = responseReceived.request().method();
            result.statusCode      = responseReceived.response().statusCode();
            result.contentLength   = responseReceived.response().body().length();
            result.originalRequest  = responseReceived.request();
            result.originalResponse = responseReceived.response();

            // Keep the compact header/coverage record for every passive response, but a clean
            // response with no technology inventory has nothing selectable in the UI and no
            // evidence to retest. Dropping only its temporary-file handles lets Burp reclaim the
            // payload after this task finishes instead of retaining a disk copy for every asset
            // in a large project. Findings and technology rows retain their full evidence.
            if (result.findings.isEmpty() && result.techFindings.isEmpty()) {
                result.rawRequest = null;
                result.rawResponse = null;
                result.originalRequest = null;
                result.originalResponse = null;
            }

            tab.onResultAdded(result);

            // Request/auth body analysis is intentionally source-aware: unlike Burp's passive
            // scan callback, this listener knows which tool produced the exchange. Publish only
            // actionable AUTH findings from sources enabled in Cookies & Auth, preserving the
            // default Proxy/Repeater/Discovery noise boundary. INFORMATION stays in Quimera.
            if (cookiesAuthSource || !interactiveCredentialFindings.isEmpty()) {
                HttpRequestResponse evidence = responseReceived;
                publishNativeAuthIssues(result, evidence);
            }

            if (cookiesAuthSource && automaticProbeEligible && settings.isGoogleApiKeyProbeEnabled()) {
                HttpRequestResponse sourceEvidence = responseReceived;
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
            // Body credential leaks are response disclosures, not request-authentication
            // heuristics. Analyze every captured response that reaches this pipeline, regardless
            // of which Burp tool produced it; Cookies & Auth source settings only govern request
            // cookies/tokens and must not make an exposed server-side secret disappear.
            final UrlAnalysisResult resultForQueuedCredentialScan = result;
            if (!interactiveSource) try {
                submitCredentialScan(toolType, () -> {
                    try {
                        if (closed.get()) return;
                        // Read bodies only when this low-priority lane reaches the exchange.
                        // responseReceived is a copyToTempFile() snapshot, so a backlog consumes
                        // Burp temporary storage rather than one heap String per response.
                        String bodyForCreds = responseReceived.response().bodyToString();
                        String requestBodyForCreds = responseReceived.request().bodyToString();
                        List<HeaderFinding> credFindings = engine.analyzeCredentialBodies(
                                url, headerMap, requestHeaderMap, bodyForCreds, requestBodyForCreds);
                        if (credFindings.isEmpty()) return;
                        UrlAnalysisResult withCreds = resultForQueuedCredentialScan.withExtraFindings(credFindings);
                        tab.onResultAdded(withCreds);
                        HttpRequestResponse credEvidence = responseReceived;
                        // A server response leaking a credential is actionable regardless of whether
                        // it was observed in Proxy, Repeater, Scanner or Intruder.  The conservative
                        // Cookies/Auth source setting controls request-side token heuristics only;
                        // using it here silently hid body leaks generated by Intruder.
                        publishNativeAuthIssues(withCreds, credEvidence);
                        if (automaticProbeEligible && settings.isGoogleApiKeyProbeEnabled()) scanForGoogleApiKeys(withCreds, credEvidence);
                    } catch (Exception ex) {
                        // ExecutorService.submit() otherwise retains this failure in its Future,
                        // making a missed disclosure indistinguishable from a clean response.
                        SafeLogging.error(api, "[Quimera] body credential analysis error for " + url + ": " + ex);
                    }
                });
            } catch (java.util.concurrent.RejectedExecutionException rejected) {
                SafeLogging.error(api, "[Quimera] leak-scan queue full; skipping body credential scan for " + url);
            }

            if (newAutoUrl) {
                HttpRequest template = responseReceived.request();
                try {
                    headerProbeExecutor.submit(() -> {
                        try {
                            if (closed.get()) return;
                            for (UrlAnalysisResult probeResult : activeScanner.scanNonCacheProbes(url, template)) {
                                if (closed.get()) return;
                                tab.onResultAdded(probeResult);
                                publishNativeProbeIssues(probeResult);
                            }
                        } catch (Exception ex) {
                            SafeLogging.error(api, "[Quimera] auto active scan error for " + url + ": " + ex.getMessage());
                        }
                    });
                } catch (java.util.concurrent.RejectedExecutionException rejected) {
                    // Do not poison dedup on a transient queue-full condition: a URL that never
                    // actually got probed must remain eligible for a later retry, same as the
                    // cache-key queue's own rejection handler just above does.
                    autoScannedUrls.remove(url);
                    SafeLogging.error(api, "[Quimera] non-cache active probe was not accepted; URL remains eligible: " + url);
                }
            }
            // No log line for the "already scanned this session" skip: a busy/dynamic site can
            // re-request the same URL hundreds of times in a session, and the one-time success log
            // above already tells the analyst this URL WAS probed, logging every later dedup hit
            // added nothing but Output-tab noise proportional to traffic volume, not to anything
            // Quimera actually did.

            if (cookiesAuthSource && automaticProbeEligible && settings.isJwtActiveProbeEnabled()) {
                HttpRequest template = responseReceived.request();
                for (JwtActiveProbe.TokenLocation loc : JwtActiveProbe.locate(template)) {
                    if (!probedJwtTokens.add(loc.token())) continue; // already probed this exact token
                    try {
                        jwtProbeExecutor.submit(() -> {
                            try {
                                if (closed.get()) return;
                                UrlAnalysisResult probeResult = jwtActiveProbe.probe(url, template, responseReceived.response(), loc);
                                if (!closed.get() && probeResult != null) {
                                    tab.onResultAdded(probeResult);
                                    publishNativeProbeIssues(probeResult);
                                }
                            } catch (Exception ex) {
                                SafeLogging.error(api, "[Quimera] JWT active probe error for " + url + ": " + ex.getMessage());
                            }
                        });
                    } catch (java.util.concurrent.RejectedExecutionException rejected) {
                        probedJwtTokens.remove(loc.token());
                        SafeLogging.error(api, "[Quimera] JWT active probe unavailable during shutdown; token remains eligible: " + url);
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
            if (cookiesAuthSource && automaticProbeEligible && settings.isSessionInvalidationProbeEnabled()
                    && toolType != ToolType.EXTENSIONS) {
                String host = HeaderAnalysisEngine.extractHost(url);
                HttpRequestResponse rr = responseReceived;
                var cookiesAndAuthConfig = settings.cookiesAndAuthConfig();
                try {
                    sessionProbeExecutor.submit(() -> {
                    try {
                        if (closed.get()) return;
                        for (UrlAnalysisResult probeResult : sessionInvalidationProbe.observe(host, rr, cookiesAndAuthConfig)) {
                            if (closed.get()) return;
                            tab.onResultAdded(probeResult);
                            publishNativeProbeIssues(probeResult);
                        }
                    } catch (Exception ex) {
                        SafeLogging.error(api, "[Quimera] session invalidation probe error for " + url + ": " + ex.getMessage());
                    }
                    });
                } catch (java.util.concurrent.RejectedExecutionException rejected) {
                    // This lane is lossless while live; rejection means shutdown rather than
                    // ordinary pressure, and must not look like a completed observation.
                    SafeLogging.error(api, "[Quimera] session observation unavailable during shutdown: " + url);
                }
            }
        } catch (Exception ex) {
            // Never interrupt live traffic because of an analysis error, but do surface it,
            // silently swallowing this made past failures indistinguishable from "nothing to report".
            SafeLogging.error(api, "[Quimera] passive capture error: " + ex);
        }
    }

    /** Automatic probes are deliberately narrower than passive observation: they send real
     * requests.  Keep them inside scope, away from Scanner-generated traffic and away from
     * static/telemetry assets. Analysts can still explicitly choose any request in the context
     * menu when that is useful. */
    static boolean isAutomaticProbeCandidate(String url, String method, short statusCode, String contentType) {
        if (url == null || method == null || !(method.equalsIgnoreCase("GET") || method.equalsIgnoreCase("HEAD"))) return false;
        if (statusCode < 200 || statusCode >= 400) return false;
        String path = url.toLowerCase(java.util.Locale.ROOT).split("[?#]", 2)[0];
        if (path.endsWith(".css") || path.endsWith(".js") || path.endsWith(".mjs")
                || path.endsWith(".map") || path.endsWith(".woff") || path.endsWith(".woff2")) return false;
        String type = contentType == null ? "" : contentType.toLowerCase(java.util.Locale.ROOT);
        return !(type.startsWith("image/") || type.startsWith("audio/") || type.startsWith("video/")
                || type.startsWith("font/") || type.contains("javascript") || type.contains("text/css"));
    }

    /** Scanner and extension traffic is already generated work; never amplify it with an
     * unattended Quimera replay. Proxy and Target are the analyst-observed sources. */
    static boolean isAutomaticProbeSource(ToolType toolType) {
        return toolType == ToolType.PROXY || toolType == ToolType.TARGET;
    }

    private boolean claimAutoCacheProbe(String host) {
        if (host == null || host.isBlank()) return false;
        return autoCacheProbeCounts.computeIfAbsent(host, ignored -> new AtomicInteger())
                .incrementAndGet() <= MAX_AUTO_CACHE_PROBES_PER_HOST;
    }

    private void releaseAutoCacheProbe(String host) {
        if (host == null || host.isBlank()) return;
        autoCacheProbeCounts.computeIfPresent(host, (ignored, count) ->
                count.decrementAndGet() <= 0 ? null : count);
    }

    private static String contentType(Map<String, String> headers) {
        return headers.getOrDefault("Content-Type", headers.getOrDefault("content-type", ""));
    }

    /** Burp can surface synthetic/malformed URLs from generated traffic. Scope evaluation rejects
     * those with IllegalArgumentException; they are never eligible for unattended probes, but
     * must not turn one bad URL into an exception storm on Burp's HTTP worker. */
    private boolean isInScopeSafely(String url) {
        if (url == null || url.isBlank()) return false;
        // Validate locally FIRST. Burp logs an exception from its dynamic scope proxy even when
        // the caller catches it, so a try/catch around isInScope() alone still pollutes Output.
        try {
            URI parsed = URI.create(url);
            if ((!("http".equalsIgnoreCase(parsed.getScheme()) || "https".equalsIgnoreCase(parsed.getScheme())))
                    || parsed.getHost() == null || parsed.getRawUserInfo() != null) return false;
        } catch (IllegalArgumentException ignored) {
            return false;
        }
        try {
            return api.scope().isInScope(url);
        } catch (IllegalArgumentException ignored) {
            return false;
        } catch (RuntimeException ignored) {
            return false;
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
        NativeAuthIssuePublisher.publish(api, result, evidence, IssueFormatting.SOURCE_COOKIES_AUTH);
    }

    private void scheduleHeaderInfluence(HttpRequestResponse baseline) {
        String key = headerInfluenceContextKey(baseline.request());
        synchronized (headerInfluenceContexts) {
            if (headerInfluenceContexts.size() >= MAX_HEADER_INFLUENCE_CONTEXTS
                    || !headerInfluenceContexts.add(key)) return;
        }
        try {
            headerInfluenceExecutor.submit(() -> {
                try {
                    if (closed.get() || !settings.isHeaderInfluenceProbeEnabled()
                            || (settings.isRestrictToScope() && !isInScopeSafely(baseline.request().url()))) {
                        headerInfluenceContexts.remove(key);
                        return;
                    }
                    headerInfluenceProbe.probe(baseline, result -> {
                        if (closed.get()) return;
                        tab.onResultAdded(result);
                        publishNativeProbeIssues(result);
                    }, this::queueHeaderInfluenceResponseAnalysis);
                    String state = headerInfluenceProbe.lastCoverage().state();
                    if (state.startsWith("cancelled") || state.equals("baseline not evaluable"))
                        headerInfluenceContexts.remove(key);
                } catch (Exception ex) {
                    headerInfluenceContexts.remove(key);
                    SafeLogging.error(api, "[Quimera] header influence probe failed: " + ex.getMessage());
                }
            });
        } catch (java.util.concurrent.RejectedExecutionException rejected) {
            headerInfluenceContexts.remove(key);
            SafeLogging.error(api, "[Quimera] header influence probe unavailable during shutdown: "
                    + baseline.request().url());
        }
    }

    /**
     * Header Influence sends through Montoya's active transport, bypassing the passive listener.
     * Feed its real responses into the same serialized leak lane, but never inspect the synthetic
     * request body/headers as authentication material. A hostile Host/Forwarded value can make a
     * framework error page disclose a credential; status code is deliberately not a gate here.
     */
    private void queueHeaderInfluenceResponseAnalysis(HttpRequestResponse exchange) {
        if (closed.get() || exchange == null || exchange.request() == null || exchange.response() == null) return;
        try {
            HttpRequestResponse snapshot = exchange.copyToTempFile();
            submitCredentialScan(null, () -> {
                try {
                if (closed.get()) return;
                String url = snapshot.request().url();
                Map<String, String> responseHeaders = new LinkedHashMap<>();
                snapshot.response().headers().forEach(h ->
                        com.b3xal.headeranalyzer.util.HeaderMaps.addResponse(responseHeaders, h.name(), h.value()));
                Map<String, String> requestHeaders = new LinkedHashMap<>();
                snapshot.request().headers().forEach(h ->
                        com.b3xal.headeranalyzer.util.HeaderMaps.addRequest(requestHeaders, h.name(), h.value()));

                // analyzeResponseHeaders retains only information disclosures for an internal
                // probe response; it cannot turn this intentionally altered exchange into a
                // false "missing security header" result.
                UrlAnalysisResult result = engine.analyzeResponseHeaders(url, responseHeaders, requestHeaders,
                        snapshot.response().statusCode(), snapshot.response().bodyToString(), snapshot.request().method());
                List<HeaderFinding> leaks = engine.analyzeCredentialBodies(url, responseHeaders, requestHeaders,
                        snapshot.response().bodyToString(), "");
                if (!leaks.isEmpty()) result = result.withExtraFindings(leaks);
                if (result.findings.isEmpty()) return;

                try {
                    result.rawRequest = snapshot.request().toString();
                    result.rawResponse = snapshot.response().toString();
                } catch (Exception ignored) { }
                result.method = snapshot.request().method();
                result.statusCode = snapshot.response().statusCode();
                result.contentLength = snapshot.response().body().length();
                result.originalRequest = snapshot.request();
                result.originalResponse = snapshot.response();
                tab.onResultAdded(result);
                publishNativeAuthIssues(result, snapshot);
                } catch (Exception ex) {
                    SafeLogging.error(api, "[Quimera] Header Influence body credential analysis error for "
                            + exchange.request().url() + ": " + ex);
                }
            });
        } catch (java.util.concurrent.RejectedExecutionException rejected) {
            SafeLogging.error(api, "[Quimera] leak-scan queue full; skipping Header Influence response for "
                    + exchange.request().url());
        } catch (Exception ex) {
            SafeLogging.error(api, "[Quimera] could not queue Header Influence response analysis: " + ex.getMessage());
        }
    }

    private static ThreadPoolExecutor credentialScanExecutor() {
        AtomicInteger sequence = new AtomicInteger();
        ThreadFactory factory = task -> {
            Thread thread = new Thread(task, "Quimera-Leaks-" + sequence.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        };
        return new ThreadPoolExecutor(1, 1, 0L, TimeUnit.MILLISECONDS,
                new PriorityBlockingQueue<>(), factory, new ThreadPoolExecutor.AbortPolicy());
    }

    private static ThreadPoolExecutor responseAnalysisExecutor() {
        AtomicInteger sequence = new AtomicInteger();
        ThreadFactory factory = task -> {
            Thread thread = new Thread(task, "Quimera-Analysis-" + sequence.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        };
        return new ThreadPoolExecutor(2, 2, 0L, TimeUnit.MILLISECONDS,
                new PriorityBlockingQueue<>(), factory, new ThreadPoolExecutor.AbortPolicy());
    }

    /** The first analysis lane gets the same bounded interactive priority as the leak lane. */
    private void submitResponseAnalysis(ToolType source, Runnable work) {
        int priority = source == ToolType.REPEATER || source == ToolType.INTRUDER ? 0 : 1;
        responseAnalysisExecutor.execute(new PrioritizedResponseAnalysis(priority,
                responseAnalysisSequence.getAndIncrement(), work));
    }

    private static final class PrioritizedResponseAnalysis implements Runnable, Comparable<PrioritizedResponseAnalysis> {
        private final int priority;
        private final long sequence;
        private final Runnable work;

        private PrioritizedResponseAnalysis(int priority, long sequence, Runnable work) {
            this.priority = priority;
            this.sequence = sequence;
            this.work = work;
        }

        @Override public void run() { work.run(); }

        @Override public int compareTo(PrioritizedResponseAnalysis other) {
            int byPriority = Integer.compare(priority, other.priority);
            return byPriority != 0 ? byPriority : Long.compare(sequence, other.sequence);
        }
    }

    /**
     * Preserve the two-worker CPU budget for credential scanning while ensuring an analyst's
     * Repeater or Intruder response is not hidden behind an arbitrary crawl/asset backlog.
     * Priority only applies to jobs that have not begun; FIFO order is retained within each tier.
     */
    private void submitCredentialScan(ToolType source, Runnable work) {
        int priority = source == ToolType.REPEATER || source == ToolType.INTRUDER ? 0 : 1;
        credentialScanExecutor.execute(new PrioritizedCredentialScan(priority,
                credentialScanSequence.getAndIncrement(), work));
    }

    private static final class PrioritizedCredentialScan implements Runnable, Comparable<PrioritizedCredentialScan> {
        private final int priority;
        private final long sequence;
        private final Runnable work;

        private PrioritizedCredentialScan(int priority, long sequence, Runnable work) {
            this.priority = priority;
            this.sequence = sequence;
            this.work = work;
        }

        @Override public void run() { work.run(); }

        @Override public int compareTo(PrioritizedCredentialScan other) {
            int byPriority = Integer.compare(priority, other.priority);
            return byPriority != 0 ? byPriority : Long.compare(sequence, other.sequence);
        }
    }

    static String headerInfluenceContextKey(HttpRequest request) {
        StringBuilder context = new StringBuilder(request.method()).append('\n').append(request.url());
        java.util.List<String> fields = new java.util.ArrayList<>();
        for (var header : request.headers()) {
            String name = header.name().toLowerCase(java.util.Locale.ROOT);
            // Custom tenant/language/rendering values can change how a header is consumed.
            // Retain duplicate fields, but ignore incidental ordering between field names.
            fields.add(name + ":" + header.value());
        }
        fields.sort(java.util.Comparator.comparing(s -> s.substring(0, s.indexOf(':'))));
        context.append('\n').append(String.join("\n", fields));
        return fingerprint(context.toString());
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
