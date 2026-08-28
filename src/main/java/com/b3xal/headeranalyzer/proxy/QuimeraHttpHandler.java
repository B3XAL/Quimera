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
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue;

/**
 * Universal passive listener: registered via {@code api.http().registerHttpHandler(...)}, this
 * sees every HTTP response that passes through Burp's core, regardless of which tool sent it ,
 * Proxy, Repeater, Intruder, Scanner, Target replays, etc. Which tools actually feed analysis is
 * configurable in Settings (QuimeraSettings#getEnabledTools), all-on by default except Extensions
 * (Quimera's own active-probe/context-menu requests are fed into the Logger explicitly elsewhere,
 * so listening to Extensions traffic too would double them up).
 *
 * Passive header reading is unconditional. Active probing (CORS Origin battery, TRACE, HSTS
 * downgrade, see {@link ActiveHeaderScanner}) is opt-in via {@link QuimeraSettings#isAutoActiveScan()}
 * (off by default, it fires real extra requests at the target); when on, it runs asynchronously on
 * {@link #activeScanExecutor} so it never blocks Burp's response-received callback, and once per
 * distinct URL ({@link #autoScannedUrls}) so revisiting/reloading a page doesn't re-probe it.
 *
 * Separately, active JWT bypass testing (alg:none / bad-signature, see {@link JwtActiveProbe}) is
 * its own opt-in via {@link QuimeraSettings#isJwtActiveProbeEnabled()} (also off by default), keyed
 * on the token value itself ({@link #probedJwtTokens}) rather than the URL, so the same JWT seen
 * across many requests only ever gets forged and replayed once.
 *
 * A third, independent opt-in, {@link SessionInvalidationProbe} via
 * {@link QuimeraSettings#isSessionInvalidationProbeEnabled()}: unlike the two probes above it
 * needs to see EVERY response (building its own recently-touched-path history), not just new
 * URLs/tokens, so it has no add-based dedup guard here, its own internal per-credential state
 * decides when a logout was actually detected and something is actually worth replaying.
 *
 * That statefulness is exactly why this one, alone among the three above it, is NOT fed EXTENSIONS-tagged
 * traffic ({@link QuimeraSettings#DEFAULT_ENABLED_TOOLS} includes it, and its own comment notes
 * re-processing Quimera's own probe requests there is normally harmless, true for the OTHER
 * passive/active checks, all idempotent overwrites of the same row). {@link SessionInvalidationProbe}
 * sends its own control/probe requests via {@code api.http().sendRequest(...)}, which come back
 * through this same handler tagged EXTENSIONS; feeding those back into its evolving
 * lastValue/touch-history state is NOT idempotent, a probe request replaying an old Bearer token
 * looks, from the inside, exactly like "this host's token just changed again", corrupting the
 * history and risking a self-triggered false-positive finding. See the ToolType.EXTENSIONS guard
 * below.
 *
 * A fourth, independent opt-in, {@link GoogleApiKeyProbe} via
 * {@link QuimeraSettings#isGoogleApiKeyProbeEnabled()} (also off by default): fires real read-only
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

    private final ExecutorService activeScanExecutor = BackgroundExecutors.bounded("Quimera-AutoActive", 2, 128);
    private final Set<String> autoScannedUrls = ConcurrentHashMap.newKeySet();
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
        activeScanExecutor.shutdownNow();
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        scopeHostTracker.observe(requestToBeSent.url());
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        try {
            String url = responseReceived.initiatingRequest().url();
            if (HeaderAnalysisEngine.isOutOfBandProbeUrl(url)) {
                return ResponseReceivedAction.continueWith(responseReceived);
            }
            var toolType = responseReceived.toolSource().toolType();

            if (!settings.isToolEnabled(toolType)) {
                return ResponseReceivedAction.continueWith(responseReceived);
            }

            if (settings.isRestrictToScope() && !api.scope().isInScope(url)) {
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

            String contentType = headerMap.getOrDefault("Content-Type",
                                 headerMap.getOrDefault("content-type", ""));
            if (!settings.shouldAnalyze(contentType, url)) {
                return ResponseReceivedAction.continueWith(responseReceived);
            }

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
                for (HeaderFinding finding : result.findings) {
                    if (finding.category != HeaderFinding.Category.AUTH) continue;
                    String searchable = (finding.headerValue == null ? "" : finding.headerValue) + " "
                            + (finding.evidence == null ? "" : finding.evidence);
                    Matcher matcher = GOOGLE_API_KEY.matcher(searchable);
                    while (matcher.find()) {
                        String key = matcher.group();
                        if (!probedGoogleApiKeyFingerprints.add(fingerprint(key))) continue;
                        String sourceLocation = finding.headerName;
                        activeScanExecutor.submit(() -> {
                            UrlAnalysisResult probeResult = googleApiKeyProbe.probe(
                                    key, result, sourceLocation, sourceEvidence);
                            if (probeResult == null) return;
                            tab.onResultAdded(probeResult);
                            publishNativeAuthIssues(probeResult, sourceEvidence);
                        });
                    }
                }
            }

            if (settings.isAutoActiveScan() && autoScannedUrls.add(url)) {
                HttpRequest template = responseReceived.initiatingRequest();
                activeScanExecutor.submit(() -> {
                    try {
                        for (UrlAnalysisResult probeResult : activeScanner.scan(url, template)) {
                            tab.onResultAdded(probeResult);
                        }
                    } catch (Exception ex) {
                        api.logging().logToError("[Quimera] auto active scan error for " + url + ": " + ex.getMessage());
                    }
                });
            }

            if (cookiesAuthSource && settings.isJwtActiveProbeEnabled()) {
                HttpRequest template = responseReceived.initiatingRequest();
                for (JwtActiveProbe.TokenLocation loc : JwtActiveProbe.locate(template)) {
                    if (!probedJwtTokens.add(loc.token())) continue; // already probed this exact token
                    activeScanExecutor.submit(() -> {
                        try {
                            UrlAnalysisResult probeResult = jwtActiveProbe.probe(url, template, responseReceived, loc);
                            if (probeResult != null) tab.onResultAdded(probeResult);
                        } catch (Exception ex) {
                            api.logging().logToError("[Quimera] JWT active probe error for " + url + ": " + ex.getMessage());
                        }
                    });
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
                activeScanExecutor.submit(() -> {
                    try {
                        for (UrlAnalysisResult probeResult : sessionInvalidationProbe.observe(host, rr, cookiesAndAuthConfig)) {
                            tab.onResultAdded(probeResult);
                        }
                    } catch (Exception ex) {
                        api.logging().logToError("[Quimera] session invalidation probe error for " + url + ": " + ex.getMessage());
                    }
                });
            }

        } catch (Exception ex) {
            // Never interrupt live traffic because of an analysis error, but do surface it , 
            // silently swallowing this made past failures indistinguishable from "nothing to report".
            api.logging().logToError("[Quimera] passive capture error: " + ex);
        }

        return ResponseReceivedAction.continueWith(responseReceived);
    }

    private void publishNativeAuthIssues(UrlAnalysisResult result, HttpRequestResponse evidence) {
        String host = HeaderAnalysisEngine.extractHost(result.url);
        for (HeaderFinding finding : result.findings) {
            String nativeTitle = IssueFormatting.nativeTitle(finding);
            if (finding.category != HeaderFinding.Category.AUTH
                    || finding.severity == Severity.INFORMATION
                    || !NativeIssueDeduplicator.first(host, nativeTitle)) continue;
            try {
                api.siteMap().add(auditIssue(
                        nativeTitle, IssueFormatting.buildDetail(finding),
                        IssueFormatting.buildRemediation(finding), result.url,
                        finding.severity.burpSeverity, finding.confidence.burpConfidence,
                        "Detected by Quimera from an enabled Cookies & Auth traffic source.",
                        null, finding.severity.burpSeverity,
                        NativeEvidenceMarker.mark(evidence, finding)));
            } catch (Exception ex) {
                api.logging().logToError("[Quimera] native auth issue error: " + ex.getMessage());
            }
        }
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
