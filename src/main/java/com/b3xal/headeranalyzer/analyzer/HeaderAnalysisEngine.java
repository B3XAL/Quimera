package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.config.CookiesAndAuthConfig;
import com.b3xal.headeranalyzer.config.QuimeraSettings;
import com.b3xal.headeranalyzer.model.Confidence;
import com.b3xal.headeranalyzer.model.HeaderFinding;
import com.b3xal.headeranalyzer.model.HeaderFinding.Category;
import com.b3xal.headeranalyzer.model.Severity;
import com.b3xal.headeranalyzer.model.TechFinding;
import com.b3xal.headeranalyzer.model.UrlAnalysisResult;

import java.net.URI;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public class HeaderAnalysisEngine {

    private static final Set<String> OUT_OF_BAND_PROBE_SUFFIXES = Set.of(
            "oastify.com", "burpcollaborator.net"
    );

    /** Burp Collaborator hosts may inherit an in-scope prefix while the actual destination is an
     * out-of-band probe service. Never treat them as application targets. */
    public static boolean isOutOfBandProbeUrl(String rawUrl) {
        String host = extractHost(rawUrl).toLowerCase(Locale.ROOT).replaceFirst("\\.$", "");
        return OUT_OF_BAND_PROBE_SUFFIXES.stream().anyMatch(s -> host.equals(s) || host.endsWith("." + s));
    }

    /** The browser bridge owns /quimera and all child routes. These are Quimera control
     * exchanges rather than target-application traffic and must never produce findings. */
    public static boolean isQuimeraInternalUrl(String rawUrl) {
        if (rawUrl == null || rawUrl.isBlank()) return false;
        try {
            String path = URI.create(rawUrl).getPath();
            if (path == null) return false;
            String lower = path.toLowerCase(Locale.ROOT);
            return lower.equals("/quimera") || lower.startsWith("/quimera/");
        } catch (IllegalArgumentException ignored) {
            return false;
        }
    }

    /** Live, editable rule set (built-in defaults + user rules from the Rules tab). */
    private final RuleStore ruleStore;

    /** User-editable "boring headers" suppression list (Settings tab), see QuimeraSettings. */
    private final QuimeraSettings settings;

    /** Cross-request cookie-lifecycle memory (stale-session-replay, static-session-on-login),
     * owned by the engine itself rather than threaded through every constructor like RuleStore/
     * settings, nothing outside the engine needs to query it directly, only reset it (see
     * {@link #clearSessionLifecycleState()}). */
    private final SessionLifecycleAnalyzer sessionLifecycle = new SessionLifecycleAnalyzer();
    private final CookieConsistencyAnalyzer cookieConsistency = new CookieConsistencyAnalyzer();
    private final CredentialCorrelationAnalyzer credentialCorrelation = new CredentialCorrelationAnalyzer();

    /** Every cookie NAME actually seen via a real Set-Cookie HTTP response header, per host.
     * {@link com.b3xal.headeranalyzer.browser.BrowserBridgeServer} queries this ({@link
     * #hasSeenCookieViaHttp}) to decide whether a cookie-flag finding reported by the browser
     * extension (from `browser.cookies`, which also sees JS-set cookies Burp's proxy never does)
     * needs forwarding into Quimera at all: if Quimera's own passive Set-Cookie analysis already
     * has this exact cookie name from real traffic, that finding is authoritative and wins, only
     * cookies Quimera genuinely never saw a Set-Cookie for (JS-only cookies) need the extension's
     * version forwarded. */
    private final ConcurrentHashMap<String, Set<String>> cookieNamesSeenByHost = new ConcurrentHashMap<>();

    // Compiled patterns cached for performance, regex text is the cache key, so edited
    // rules simply compile under a new key rather than needing invalidation.
    private static final ConcurrentHashMap<String, Optional<Pattern>> PATTERN_CACHE =
            new ConcurrentHashMap<>();

    public HeaderAnalysisEngine(RuleStore ruleStore, QuimeraSettings settings) {
        this.ruleStore = ruleStore;
        this.settings  = settings;
    }

    /**
     * Context-aware entry point. Filters out findings that are not applicable given the
     * HTTP status code and Content-Type of the response (e.g. no CSP on a 401 challenge).
     * method is optional (null degrades to "unknown", the pre-existing behaviour), pass it
     * whenever available so OPTIONS responses (CORS preflight / capability negotiation, never
     * rendered or acted on as a document by a browser) get the same "info-disclosure only"
     * treatment as an error page.
     */
    public UrlAnalysisResult analyze(String rawUrl, Map<String, String> headers, int statusCode, String method) {
        if (isOutOfBandProbeUrl(rawUrl) || isQuimeraInternalUrl(rawUrl)) {
            return new UrlAnalysisResult(normalizeUrl(rawUrl), extractHost(rawUrl), extractPath(rawUrl),
                    List.of(), headers, List.of());
        }
        UrlAnalysisResult result = analyze(rawUrl, headers);
        String ct = "";
        for (Map.Entry<String, String> e : headers.entrySet()) {
            if ("content-type".equalsIgnoreCase(e.getKey())) {
                ct = e.getValue() != null ? e.getValue() : "";
                break;
            }
        }
        // result.findings is intentionally immutable (UrlAnalysisResult exposes a read-only list
        // to callers), filter/sort a mutable copy instead of mutating it in place, which threw
        // UnsupportedOperationException on every single call and silently killed all analysis.
        List<HeaderFinding> filtered = new ArrayList<>(result.findings);
        applyContextFilter(filtered, statusCode, ct, rawUrl, method);
        // User-editable "boring headers" list (Settings tab): the analyst's own known-noisy
        // headers never get reported, regardless of which rule would otherwise fire on them.
        filtered.removeIf(f -> settings.isHeaderSuppressed(f.headerName));
        filtered.sort(Comparator.comparingInt(f -> f.severity.order));
        UrlAnalysisResult contextual = new UrlAnalysisResult(result.url, result.host, result.path,
                filtered, result.rawHeaders, result.techFindings);
        return applyHstsValueContext(contextual, headers);
    }

    private static final Pattern HSTS_MAX_AGE = Pattern.compile(
            "(?i)(?:^|;)\\s*max-age\\s*=\\s*\"?(\\d+)\"?\\s*(?=;|$)");
    private static final Pattern HSTS_PRELOAD = Pattern.compile(
            "(?i)(?:^|;)\\s*preload\\s*(?=;|$)");

    /** Re-evaluates max-age numerically: digit-count regexes miss part of the interval below a
     * year. RFC 6797 permits a quoted-string whose unescaped content is delta-seconds. */
    private static UrlAnalysisResult applyHstsValueContext(UrlAnalysisResult result,
                                                            Map<String, String> headers) {
        String hsts = getHeaderCI(headers, "Strict-Transport-Security");
        if (hsts == null || hsts.isBlank()) return result;
        String firstLine = hsts.split("\\n", 2)[0].trim();
        java.util.regex.Matcher matcher = HSTS_MAX_AGE.matcher(firstLine);
        List<HeaderFinding> adjusted = new ArrayList<>();
        for (HeaderFinding finding : result.findings) {
            if (!finding.issueName.equals("HSTS max-age below recommended minimum")
                    && !finding.issueName.equals("HSTS policy explicitly disabled (max-age=0)")) {
                adjusted.add(finding);
            }
        }
        if (!matcher.find()) return result.withReplacedFindings(adjusted);

        java.math.BigInteger maxAge = new java.math.BigInteger(matcher.group(1));
        java.math.BigInteger year = java.math.BigInteger.valueOf(31_536_000L);
        if (maxAge.signum() == 0) {
            adjusted.add(new HeaderFinding("HSTS policy explicitly disabled (max-age=0)",
                    "Strict-Transport-Security", hsts,
                    "The HSTS field sets max-age=0, instructing browsers to remove the HSTS policy. " +
                            "Use this only for a deliberate rollback; it provides no downgrade protection.",
                    "Strict-Transport-Security max-age is 0.", Severity.MEDIUM, Confidence.CERTAIN,
                    Category.SECURITY_MISCONFIGURED,
                    "https://www.rfc-editor.org/rfc/rfc6797.html#section-6.1.1"));
        } else if (maxAge.compareTo(year) < 0 && HSTS_PRELOAD.matcher(firstLine).find()) {
            adjusted.add(new HeaderFinding("HSTS preload max-age requirement not met",
                    "Strict-Transport-Security", hsts,
                    "The policy declares 'preload', but its max-age is below the public preload-list " +
                            "eligibility requirement of 31536000 seconds. The HSTS policy itself remains valid; " +
                            "this only means it does not meet current preload submission requirements.",
                    "Observed max-age=" + maxAge + " seconds with preload; required for preload eligibility: " +
                            "31536000 seconds.", Severity.INFORMATION, Confidence.CERTAIN,
                    Category.ADVISABLE,
                    "https://hstspreload.org/#submission-requirements"));
        }
        adjusted.sort(Comparator.comparingInt(f -> f.severity.order));
        return result.withReplacedFindings(adjusted);
    }

    /**
     * Same as {@link #analyze(String, Map, int, String)} plus a body cross-reference: if any
     * cookie value set on this same response also appears in the response body alongside a
     * localStorage/sessionStorage call, that's flagged too (see WebStorageAnalyzer), and a handful
     * of findings whose real-world impact depends on whether THIS specific page is sensitive/
     * critical get their severity adjusted accordingly (see {@link #applySensitivityAdjustment}).
     * body is optional, pass null or empty if unavailable, this degrades gracefully to the
     * header-only behavior. No request headers, so no JWT/Basic-Auth/Bearer recognition, see the
     * 6-arg overload for that.
     */
    public UrlAnalysisResult analyze(String rawUrl, Map<String, String> headers, int statusCode, String body, String method) {
        return analyze(rawUrl, headers, Map.of(), statusCode, body, method, false);
    }

    /**
     * Same as the 5-arg overload, plus REQUEST headers so {@link AuthHeaderAnalyzer} can recognize
     * JWT/HTTP-Basic/Bearer/API-key tokens, those live in the request's Authorization/Cookie/
     * X-Api-Key-style headers, not the response headers everything else here reads. requestHeaders
     * may be null/empty (older call sites, synthetic active-probe requests), this degrades
     * gracefully to no auth-token findings, same shape as passing a null body.
     */
    public UrlAnalysisResult analyze(String rawUrl, Map<String, String> headers,
                                      Map<String, String> requestHeaders, int statusCode, String body, String method) {
        return analyze(rawUrl, headers, requestHeaders, statusCode, body, method, true);
    }

    /**
     * Source-aware variant used by the universal HTTP listener. When requestAuthAllowed is false,
     * response analysis (including Set-Cookie) still runs, while request-derived auth/token and
     * credential-lifecycle checks are skipped to avoid synthetic Scanner/Extension probe noise.
     */
    public UrlAnalysisResult analyze(String rawUrl, Map<String, String> headers,
                                      Map<String, String> requestHeaders, int statusCode, String body,
                                      String method, boolean requestAuthAllowed) {
        return analyze(rawUrl, headers, requestHeaders, statusCode, body, method,
                requestAuthAllowed, null);
    }

    /** Full exchange variant; requestBody is inspected only when Cookies & Auth is enabled for
     * this traffic source, preserving the default noise boundary for Scanner/Extensions. */
    public UrlAnalysisResult analyze(String rawUrl, Map<String, String> headers,
                                      Map<String, String> requestHeaders, int statusCode, String body,
                                      String method, boolean requestAuthAllowed, String requestBody) {
        UrlAnalysisResult result = analyze(rawUrl, headers, statusCode, method);

        // Montoya may return a placeholder exchange after a timeout/connection failure. It has
        // no real HTTP response (status 0), so there is nothing from which to infer missing
        // security headers, cookies, credentials or response/body findings.
        if (statusCode < 100) return result;

        CookiesAndAuthConfig cookiesAndAuthConfig = settings.cookiesAndAuthConfig();

        List<HeaderFinding> extra = WebStorageAnalyzer.analyze(body,
                getHeaderCI(headers, "Set-Cookie"), cookiesAndAuthConfig);
        if (!extra.isEmpty()) result = result.withExtraFindings(extra);

        List<HeaderFinding> jsCookieFindings = CookieAnalyzer.analyzeJsCookies(body, cookiesAndAuthConfig);
        if (!jsCookieFindings.isEmpty()) result = result.withExtraFindings(jsCookieFindings);

        result = applyMimeAndCacheContext(result, headers, requestHeaders, statusCode, body,
                method, requestAuthAllowed, cookiesAndAuthConfig);
        result = applyInfrastructureContext(result, headers, requestHeaders);
        result = applySensitivityAdjustment(result, body);

        if (requestHeaders != null && !requestHeaders.isEmpty()) {
            // Vary/Origin is a response-security check, not Cookies & Auth inventory. It remains
            // useful for every enabled traffic source even when request auth inspection is off.
            List<HeaderFinding> varyFindings = checkVaryOriginGap(headers, requestHeaders);
            if (!varyFindings.isEmpty()) result = result.withExtraFindings(varyFindings);
        }

        if (requestAuthAllowed && requestHeaders != null && !requestHeaders.isEmpty()) {
            List<HeaderFinding> authFindings = AuthHeaderAnalyzer.analyze(rawUrl, requestHeaders,
                    cookiesAndAuthConfig);
            if (!authFindings.isEmpty()) result = result.withExtraFindings(authFindings);
        }

        if (requestAuthAllowed) {
            List<HeaderFinding> requestBodyFindings = CredentialBodyAnalyzer.analyze(requestBody,
                    getHeaderCI(requestHeaders, "Content-Type"), "request", cookiesAndAuthConfig);
            List<HeaderFinding> responseBodyFindings = CredentialBodyAnalyzer.analyze(body,
                    getHeaderCI(headers, "Content-Type"), "response", cookiesAndAuthConfig);
            if (!requestBodyFindings.isEmpty()) result = result.withExtraFindings(requestBodyFindings);
            if (!responseBodyFindings.isEmpty()) result = result.withExtraFindings(responseBodyFindings);
        }

        if (requestAuthAllowed) {
            List<HeaderFinding> sessionFindings = sessionLifecycle.observe(
                    result.host, result.path, headers, requestHeaders, statusCode, cookiesAndAuthConfig);
            if (!sessionFindings.isEmpty()) result = result.withExtraFindings(sessionFindings);

            List<HeaderFinding> correlationFindings = credentialCorrelation.observe(
                    rawUrl, headers, requestHeaders, cookiesAndAuthConfig);
            if (!correlationFindings.isEmpty()) result = result.withExtraFindings(correlationFindings);
        }

        return result;
    }

    /** Removes reflected client-facing forwarding values and avoids claiming a confirmed origin
     * bypass from a hostname alone. Technology/version findings are deliberately not adjusted. */
    private static UrlAnalysisResult applyInfrastructureContext(UrlAnalysisResult result,
                                                                 Map<String, String> responseHeaders,
                                                                 Map<String, String> requestHeaders) {
        String forwardedHost = getHeaderCI(responseHeaders, "X-Forwarded-Host");
        String requestHost = getHeaderCI(requestHeaders, "Host");
        String requestRealIp = getHeaderCI(requestHeaders, "X-Real-IP");
        List<HeaderFinding> adjusted = new ArrayList<>();
        boolean changed = false;
        for (HeaderFinding finding : result.findings) {
            if ("Internal hostname disclosed via X-Forwarded-Host".equals(finding.issueName)) {
                String candidate = stripPort(forwardedHost);
                if (sameHost(candidate, result.host) || sameHost(candidate, stripPort(requestHost))) {
                    changed = true; // ordinary echo of the public request Host
                    continue;
                }
                adjusted.add(new HeaderFinding(finding.issueName, finding.headerName, finding.headerValue,
                        "The response exposes an X-Forwarded-Host value different from the public request " +
                                "host. It may identify an upstream route or origin, but passive observation " +
                                "alone does not prove that it is reachable or bypasses a CDN/WAF.",
                        finding.evidence, Severity.MEDIUM, Confidence.TENTATIVE, finding.category,
                        "https://portswigger.net/web-security/host-header"));
                changed = true;
                continue;
            }
            if ("IP address disclosed via X-Real-IP response header".equals(finding.issueName)
                    && requestRealIp != null && requestRealIp.trim().equalsIgnoreCase(finding.headerValue.trim())) {
                changed = true; // reflected request metadata, not newly disclosed infrastructure
                continue;
            }
            adjusted.add(finding);
        }
        return changed ? result.withReplacedFindings(adjusted) : result;
    }

    private static String stripPort(String value) {
        if (value == null) return null;
        String first = value.split("[,\\n]", 2)[0].trim();
        if (first.startsWith("[")) {
            int end = first.indexOf(']');
            return end > 0 ? first.substring(1, end) : first;
        }
        int colon = first.lastIndexOf(':');
        return colon > 0 && first.indexOf(':') == colon ? first.substring(0, colon) : first;
    }

    private static boolean sameHost(String left, String right) {
        if (left == null || right == null) return false;
        String a = left.trim().replaceFirst("\\.$", "");
        String b = right.trim().replaceFirst("\\.$", "");
        return !a.isEmpty() && a.equalsIgnoreCase(b);
    }

    /** JavaScript MIME type essences accepted by the MIME Sniffing/HTML standards. Most are
     * legacy aliases, but browsers still classify them as JavaScript, so reporting a missing
     * nosniff header for one of them would claim protection that nosniff would not add. */
    private static final Set<String> JAVASCRIPT_MIME_TYPES = Set.of(
            "application/ecmascript", "application/javascript",
            "application/x-ecmascript", "application/x-javascript",
            "text/ecmascript", "text/javascript", "text/javascript1.0",
            "text/javascript1.1", "text/javascript1.2", "text/javascript1.3",
            "text/javascript1.4", "text/javascript1.5", "text/jscript",
            "text/livescript", "text/x-ecmascript", "text/x-javascript"
    );

    /** Fetch destinations for which the standard applies the script-like nosniff check. */
    private static final Set<String> SCRIPT_LIKE_DESTINATIONS = Set.of(
            "audioworklet", "paintworklet", "script", "serviceworker", "sharedworker", "worker"
    );

    private static final Set<String> REFERRER_POLICIES = Set.of(
            "no-referrer", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin",
            "same-origin", "strict-origin", "strict-origin-when-cross-origin", "unsafe-url"
    );

    private static final Pattern SENSITIVE_RESPONSE_VALUE = Pattern.compile(
            "(?i)[\"'](?:access[_-]?token|refresh[_-]?token|id[_-]?token|client[_-]?secret|" +
            "api[_-]?key|session[_-]?id|password|passwd)[\"']\\s*:\\s*[\"'][^\"']{4,}"
    );

    /**
     * Turns two broad header-presence rules into response-risk findings. The raw rule engine still
     * detects malformed/present values consistently; this layer decides whether the current
     * response has a browser execution or confidentiality context that makes reporting useful.
     */
    private static UrlAnalysisResult applyMimeAndCacheContext(
            UrlAnalysisResult result, Map<String, String> responseHeaders,
            Map<String, String> requestHeaders, int statusCode, String body, String method,
            boolean requestAuthAllowed, CookiesAndAuthConfig config) {
        boolean hasMimeFinding = result.findings.stream().anyMatch(f ->
                f.headerName.equalsIgnoreCase("X-Content-Type-Options"));
        boolean hasMissingCache = result.findings.stream().anyMatch(f ->
                "Missing Cache-Control header".equals(f.issueName));
        boolean hasPublicCache = result.findings.stream().anyMatch(f ->
                "Cache-Control set to public".equals(f.issueName));
        if (!hasMimeFinding && !hasMissingCache && !hasPublicCache) return result;

        boolean keepMime = isMimeSniffingRelevant(responseHeaders, requestHeaders, result.url, method);
        String cacheReason = hasMissingCache || hasPublicCache
                ? cacheSensitivityReason(result.path, body, responseHeaders, requestHeaders,
                        requestAuthAllowed, config)
                : null;
        boolean cacheableMethod = method == null || method.equalsIgnoreCase("GET")
                || method.equalsIgnoreCase("HEAD");
        boolean cacheableStatus = statusCode == 200 || statusCode == 203 || statusCode == 206
                || statusCode == 300 || statusCode == 301 || statusCode == 308;
        String observedCache = observedSharedCacheEvidence(responseHeaders);

        List<HeaderFinding> filtered = new ArrayList<>(result.findings.size());
        boolean changed = false;
        for (HeaderFinding finding : result.findings) {
            if (finding.headerName.equalsIgnoreCase("X-Content-Type-Options") && !keepMime) {
                changed = true;
                continue;
            }
            if ("Missing Cache-Control header".equals(finding.issueName)) {
                if (!cacheableMethod || !cacheableStatus || cacheReason == null) {
                    changed = true;
                    continue;
                }
                Severity severity = observedCache != null && observedCache.startsWith("CACHEABLE:")
                        ? Severity.MEDIUM : Severity.LOW;
                String cacheObservation = observedCache == null ? "No shared-cache status was observed."
                        : observedCache.substring(observedCache.indexOf(':') + 1);
                filtered.add(new HeaderFinding(
                        finding.issueName, finding.headerName, finding.headerValue,
                        "Cache-Control is absent on a response that has a concrete sensitivity signal (" +
                        cacheReason + "). Browsers may retain it, and shared caches can store eligible " +
                        "responses unless the origin expresses an explicit policy. Use 'Cache-Control: " +
                        "no-store' for data that must not be retained, or an appropriately scoped 'private' " +
                        "policy when browser caching is acceptable.",
                        finding.evidence + " Sensitivity: " + cacheReason + ". " + cacheObservation,
                        severity, Confidence.CERTAIN, finding.category, finding.referenceUrl));
                changed = true;
                continue;
            }
            if ("Cache-Control set to public".equals(finding.issueName)) {
                String cacheControl = getHeaderCI(responseHeaders, "Cache-Control");
                boolean overridden = cacheControl != null && Arrays.stream(cacheControl.split(","))
                        .map(String::trim).anyMatch(v -> v.equalsIgnoreCase("private")
                                || v.equalsIgnoreCase("no-store"));
                if (cacheReason == null || overridden) {
                    changed = true;
                    continue;
                }
                boolean visiblyCached = observedCache != null && observedCache.startsWith("CACHEABLE:");
                filtered.add(new HeaderFinding(finding.issueName, finding.headerName, finding.headerValue,
                        "Cache-Control explicitly permits shared caching on a response with a concrete " +
                                "sensitivity signal. Confirm that cache keys isolate users, or use 'private' " +
                                "or 'no-store' as appropriate.",
                        finding.evidence + " Sensitivity: " + cacheReason + ". " +
                                (observedCache == null ? "No shared-cache status was observed."
                                        : observedCache.substring(observedCache.indexOf(':') + 1)),
                        visiblyCached ? Severity.MEDIUM : Severity.LOW,
                        visiblyCached ? Confidence.CERTAIN : Confidence.FIRM,
                        finding.category, "https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2.9"));
                changed = true;
                continue;
            }
            filtered.add(finding);
        }
        return changed ? result.withReplacedFindings(filtered) : result;
    }

    static boolean isMimeSniffingRelevant(Map<String, String> responseHeaders,
                                           Map<String, String> requestHeaders,
                                           String rawUrl, String method) {
        if (method != null && !method.equalsIgnoreCase("GET") && !method.equalsIgnoreCase("HEAD")) {
            return false;
        }
        String destination = getHeaderCI(requestHeaders, "Sec-Fetch-Dest");
        String normalizedDestination = destination == null ? null
                : destination.trim().toLowerCase(Locale.ROOT);
        boolean scriptContext = normalizedDestination != null
                && SCRIPT_LIKE_DESTINATIONS.contains(normalizedDestination);
        boolean styleContext = "style".equals(normalizedDestination);

        // A real Sec-Fetch-Dest is stronger than the URL suffix. For example, navigating directly
        // to /debug.js has destination=document and nosniff has no effect on that response.
        // Only fall back to the suffix for older/non-browser traffic where the destination is
        // genuinely unavailable.
        String path = extractPath(rawUrl).toLowerCase(Locale.ROOT);
        int dot = path.lastIndexOf('.');
        String extension = dot >= 0 ? path.substring(dot) : "";
        if (normalizedDestination == null || normalizedDestination.isBlank()) {
            scriptContext = extension.equals(".js") || extension.equals(".mjs") || extension.equals(".cjs");
            styleContext = extension.equals(".css");
        }

        // The Fetch nosniff algorithm only acts on script-like and style destinations. Missing
        // Content-Type on an arbitrary HTML/API/download response is therefore not, by itself,
        // evidence for an X-Content-Type-Options finding.
        if (!scriptContext && !styleContext) return false;

        String contentType = getHeaderCI(responseHeaders, "Content-Type");
        if (contentType == null || contentType.isBlank()) return true;
        String mime = contentType.split(";", 2)[0].trim().toLowerCase(Locale.ROOT);
        if (scriptContext) {
            if (JAVASCRIPT_MIME_TYPES.contains(mime)) return false;
            // Fetch already blocks these MIME types for script-like destinations even without
            // nosniff. Recommending nosniff on that response would not change browser behaviour.
            return !mime.startsWith("audio/") && !mime.startsWith("image/")
                    && !mime.startsWith("video/") && !mime.equals("text/csv");
        }
        return !mime.equals("text/css");
    }

    private static String cacheSensitivityReason(String path, String body,
                                                  Map<String, String> responseHeaders,
                                                  Map<String, String> requestHeaders,
                                                  boolean requestAuthAllowed,
                                                  CookiesAndAuthConfig config) {
        String pageReason = PageSensitivity.sensitiveReason(path, body);
        if (pageReason != null) return pageReason;

        String vary = getHeaderCI(responseHeaders, "Vary");
        if (vary != null && Arrays.stream(vary.split(","))
                .anyMatch(v -> v.trim().equalsIgnoreCase("Cookie"))) {
            return "Vary: Cookie indicates a user-dependent representation";
        }

        String setCookie = getHeaderCI(responseHeaders, "Set-Cookie");
        if (setCookie != null) {
            for (String line : setCookie.split("\\n")) {
                String name = CookieAnalyzer.parseName(line);
                if (name.isBlank() || CookieAnalyzer.isKnownTrackingCookie(name, config)) continue;
                boolean httpOnly = CookieAnalyzer.parseAttrs(line).contains("httponly");
                boolean structuredJwt = !StructuredCookieJwtAnalyzer.extract(
                        CookieAnalyzer.parseValue(line)).isEmpty();
                if (httpOnly || structuredJwt || CookieAnalyzer.nameLooksSensitive(name, config)) {
                    return "response issues session/auth cookie '" + name + "'";
                }
            }
        }

        if (requestAuthAllowed && requestHeaders != null) {
            String authorization = getHeaderCI(requestHeaders, "Authorization");
            if (authorization != null && !authorization.isBlank()) return "request is authenticated via Authorization";
            for (String name : AuthHeaderAnalyzer.allApiKeyHeaders(config)) {
                String value = getHeaderCI(requestHeaders, name);
                if (value != null && !value.isBlank()) return "request carries authentication header '" + name + "'";
            }
            String cookie = getHeaderCI(requestHeaders, "Cookie");
            if (cookie != null) {
                for (String pair : cookie.split(";")) {
                    int eq = pair.indexOf('=');
                    if (eq <= 0) continue;
                    String name = pair.substring(0, eq).trim();
                    String value = pair.substring(eq + 1).trim();
                    if (CookieAnalyzer.nameLooksSensitive(name, config)
                            || !StructuredCookieJwtAnalyzer.extract(value).isEmpty()) {
                        return "request carries session/auth cookie '" + name + "'";
                    }
                }
            }
        }

        if (body != null && body.length() <= 5_000_000
                && SENSITIVE_RESPONSE_VALUE.matcher(body).find()) {
            return "response body contains a credential-shaped field with a non-empty value";
        }
        return null;
    }

    /** Prefix CACHEABLE means the edge visibly stored/considered the response cacheable. */
    private static String observedSharedCacheEvidence(Map<String, String> headers) {
        String cf = getHeaderCI(headers, "CF-Cache-Status");
        if (cf != null && !cf.isBlank()) {
            String value = cf.trim().toUpperCase(Locale.ROOT);
            if (Set.of("HIT", "STALE", "UPDATING", "REVALIDATED", "EXPIRED").contains(value)) {
                return "CACHEABLE:CF-Cache-Status: " + value +
                        " shows that Cloudflare's cache participates in this resource.";
            }
            if (value.equals("MISS")) {
                return "CACHE_MISS:CF-Cache-Status: MISS shows that the object was not served from cache; " +
                        "it does not prove that this response was stored afterwards.";
            }
            if (value.equals("DYNAMIC") || value.equals("BYPASS")) {
                return "NOT_EDGE_CACHED:CF-Cache-Status: " + value +
                        " indicates this response was not served from Cloudflare cache, but it does not " +
                        "control browser or other intermediary caches.";
            }
        }
        String xCache = getHeaderCI(headers, "X-Cache");
        if (xCache != null && xCache.toUpperCase(Locale.ROOT).contains("HIT")) {
            return "CACHEABLE:X-Cache reports a cache hit (" + xCache.trim() + ").";
        }
        String age = getHeaderCI(headers, "Age");
        if (age != null) {
            try {
                if (Long.parseLong(age.trim()) > 0) return "CACHEABLE:Age: " + age.trim() +
                        " is direct evidence that a cache stored the response.";
            } catch (NumberFormatException ignored) { }
        }
        return null;
    }

    /** QuimeraTab#clearAll wipes the whole session's captured data, the cross-request cookie-
     * lifecycle memory {@link SessionLifecycleAnalyzer} keeps needs to reset the same way, or a
     * value cleared/granted before Clear could still trigger a finding against traffic captured
     * long after, comparing across two unrelated capture sessions. */
    public void clearSessionLifecycleState() {
        sessionLifecycle.clear();
        cookieConsistency.clear();
        credentialCorrelation.clear();
        cookieNamesSeenByHost.clear();
    }

    private void recordCookieNamesSeen(String host, String setCookieHeader) {
        if (setCookieHeader == null || setCookieHeader.isBlank()) return;
        for (String cookieLine : setCookieHeader.split("\n")) {
            String name = CookieAnalyzer.parseName(cookieLine);
            if (name != null && !name.isBlank()) {
                cookieNamesSeenByHost.computeIfAbsent(host, h -> ConcurrentHashMap.newKeySet()).add(name);
            }
        }
    }

    /** See {@link #cookieNamesSeenByHost}'s own javadoc: true if Quimera's own passive analysis
     * has already seen a real Set-Cookie for this exact cookie name on this host. */
    public boolean hasSeenCookieViaHttp(String host, String cookieName) {
        Set<String> names = cookieNamesSeenByHost.get(host);
        return names != null && names.contains(cookieName);
    }

    /** If Access-Control-Allow-Origin echoes back the exact request Origin (not a static "*"), the
     * response is being generated dynamically per-Origin. Without "Vary: Origin" (or "Vary: *"), a
     * shared cache (CDN, reverse proxy) keys purely on the URL by default: once this response is
     * cached for one origin, ANY other origin requesting the same URL can be served that same
     * cached, origin-permissive response, a CORS bypass mediated entirely through the cache rather
     * than a validation bug in the application itself. See
     * https://www.pixelite.co.nz/article/cors-caching-and-the-vary-http-header/. FIRM, not CERTAIN:
     * inferred from a single request/response pair matching, a server that always echoes back
     * exactly one hardcoded partner origin (coincidentally the same one requested here) would also
     * match this shape without actually being vulnerable, genuine dynamic reflection can't be
     * proven from one sample the way a direct value check can. */
    private static List<HeaderFinding> checkVaryOriginGap(Map<String, String> headers, Map<String, String> requestHeaders) {
        String reqOrigin = getHeaderCI(requestHeaders, "Origin");
        if (reqOrigin == null || reqOrigin.isBlank()) return List.of();
        String acao = getHeaderCI(headers, "Access-Control-Allow-Origin");
        if (acao == null || !acao.trim().equalsIgnoreCase(reqOrigin.trim())) return List.of();
        String vary = getHeaderCI(headers, "Vary");
        boolean variesOnOrigin = vary != null && Arrays.stream(vary.split(","))
                .anyMatch(v -> v.trim().equalsIgnoreCase("Origin") || v.trim().equals("*"));
        if (variesOnOrigin) return List.of();
        return List.of(new HeaderFinding(
            "Missing Vary: Origin on dynamic CORS response",
            "Access-Control-Allow-Origin",
            acao,
            "Access-Control-Allow-Origin dynamically reflects this request's Origin (" + reqOrigin + ") " +
            "but the response carries no 'Vary: Origin' (or 'Vary: *'). Shared caches (CDNs, reverse " +
            "proxies) key their cache purely on the URL by default, so once this response is cached for " +
            "one origin, any other origin requesting the same URL can be served the SAME cached, " +
            "origin-permissive response, a CORS bypass mediated through the cache rather than a " +
            "validation bug in the application itself. Add 'Vary: Origin' whenever Access-Control-" +
            "Allow-Origin is generated dynamically from the request's Origin header.",
            "Origin: " + reqOrigin + "  ->  Access-Control-Allow-Origin: " + acao
                    + "  |  Vary: " + (vary == null ? "(absent)" : vary),
            Severity.MEDIUM, Confidence.FIRM, Category.SECURITY_MISCONFIGURED,
            "https://www.pixelite.co.nz/article/cors-caching-and-the-vary-http-header/"));
    }

    private static String getHeaderCI(Map<String, String> headers, String name) {
        if (headers == null) return null;
        for (Map.Entry<String, String> e : headers.entrySet()) {
            if (name.equalsIgnoreCase(e.getKey())) return e.getValue();
        }
        return null;
    }

    /**
     * Findings whose severity swings by page sensitivity, mapped to {sensitive-page severity,
     * non-sensitive-page severity}. Deliberately NOT every finding: only ones whose threat model is
     * genuinely about what can be done ON this specific page (clickjacking a UI action, caching or
     * leaking THIS response's own data). Findings whose blast radius is origin-wide regardless of
     * which page has the bug (missing CSP overall enabling XSS anywhere on the origin, missing HSTS,
     * missing X-Content-Type-Options, cookie flags) are deliberately excluded, an XSS or downgrade
     * bug on a "boring" page can still steal the same origin-wide session cookie, so downgrading
     * those on a non-sensitive page would UNDERSTATE real risk, exactly what this feature must not do.
     * X-Content-Type-Options and missing Cache-Control are handled separately by
     * applyMimeAndCacheContext because MIME destination and concrete cache-sensitivity signals are
     * more precise than this binary page-level severity mapping.
     */
    private static final Map<String, Severity[]> SENSITIVITY_SEVERITY_BY_ISSUE = Map.of(
        "Missing Clickjacking Protection",             new Severity[]{Severity.HIGH,   Severity.LOW},
        "CSP: frame-ancestors directive missing",      new Severity[]{Severity.MEDIUM, Severity.LOW},
        "Referrer-Policy set to unsafe-url",            new Severity[]{Severity.HIGH,   Severity.LOW}
    );

    private static UrlAnalysisResult applySensitivityAdjustment(UrlAnalysisResult result, String body) {
        // Cheap bail-out: none of the adjustable issues survived applyContextFilter on this
        // response (the common case, e.g. any asset/API/redirect response already dropped all of
        // them), skip the PageSensitivity check entirely.
        boolean anyAdjustable = result.findings.stream().anyMatch(f -> SENSITIVITY_SEVERITY_BY_ISSUE.containsKey(f.issueName));
        if (!anyAdjustable) return result;

        String reason = PageSensitivity.sensitiveReason(result.path, body);
        boolean sensitive = reason != null;

        List<HeaderFinding> adjusted = new ArrayList<>(result.findings.size());
        boolean changed = false;
        for (HeaderFinding f : result.findings) {
            Severity[] mapping = SENSITIVITY_SEVERITY_BY_ISSUE.get(f.issueName);
            Severity target = mapping == null ? null : mapping[sensitive ? 0 : 1];
            if (target != null && target != f.severity) {
                changed = true;
                String note = sensitive
                    ? " [Severity raised: this page matches a sensitive-page signal (" + reason + "), " +
                      "the real-world impact of this finding concentrates on pages like this one.]"
                    : " [Severity lowered: no sensitive-page signal found on this specific page " +
                      "(no matching URL keyword, no password field in the body), reducing this " +
                      "particular instance's immediate real-world impact.]";
                adjusted.add(new HeaderFinding(f.issueName, f.headerName, f.headerValue,
                        f.description + note, f.evidence, target, f.confidence, f.category, f.referenceUrl));
            } else {
                adjusted.add(f);
            }
        }
        return changed ? result.withReplacedFindings(adjusted) : result;
    }

    /** Extensions whose response is unambiguously a static asset, not a browsable HTML document,
     * used as a fallback signal in {@link #applyContextFilter} only when Content-Type is missing
     * entirely. Dynamic routes / misconfigured gateways routinely serve .js/.css bundles with no
     * Content-Type (or a generic one Content-Type-based sniffing already handles, e.g. text/plain
     * -> isApi), leaving the Content-Type-only check no signal at all to work with, and "Missing
     * X-Frame-Options" firing on a plain .js response was exactly that gap. */
    private static final Set<String> ASSET_EXTENSIONS = Set.of(
        ".js", ".mjs", ".cjs", ".css", ".map",
        ".woff", ".woff2", ".ttf", ".otf", ".eot",
        ".svg", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".avif",
        ".mp4", ".mp3", ".wav", ".ogg", ".webm", ".pdf"
    );

    private static boolean looksLikeAssetByExtension(String rawUrl) {
        try {
            String path = extractPath(rawUrl).toLowerCase(Locale.ROOT);
            int dot = path.lastIndexOf('.');
            return dot >= 0 && ASSET_EXTENSIONS.contains(path.substring(dot));
        } catch (Exception ex) {
            return false;
        }
    }

    private static void applyContextFilter(List<HeaderFinding> findings, int status, String contentType,
                                            String rawUrl, String method) {
        // A status below 100 is not an HTTP response. Burp/Montoya uses status 0 for failed,
        // timed-out or otherwise incomplete exchanges; treating its empty header map as a real
        // response would manufacture every "Missing ..." finding.
        if (status < 100) {
            findings.clear();
            return;
        }

        String ct          = contentType.toLowerCase(Locale.ROOT);
        boolean isHtml     = ct.contains("text/html") || ct.contains("xhtml");
        boolean isRedirect = status >= 300 && status < 400;
        boolean isEmpty    = status == 204 || status == 304;
        boolean isAuth     = status == 401 || status == 407;
        boolean isAsset    = ct.startsWith("image/") || ct.startsWith("font/")
                          || ct.contains("text/css") || ct.contains("javascript")
                          || ct.startsWith("application/octet-stream")
                          || (ct.isBlank() && looksLikeAssetByExtension(rawUrl));
        boolean isApi      = !isHtml && !isAsset
                          && (ct.contains("json") || ct.contains("xml") || ct.contains("text/plain"));
        // 4xx/5xx error pages (404, 500, 403, ...): not the real document the app is meant to
        // serve, so browser-rendering policies about it (CSP/XFO/etc, see browserRenderingHeader
        // below) are noise there, same reasoning already applied to redirects/auth challenges.
        boolean isError    = status >= 400;
        // OPTIONS is a CORS-preflight / capability-negotiation exchange, a browser never renders
        // or acts on it as a document or API response, only reads a couple of specific CORS
        // response headers off it. Nothing about its security POSTURE is meaningful there, not
        // CSP/XFO, not CORS wildcards, not cookie flags, not cache-control, only pure information
        // disclosure ("this header reveals server tech") still leaks regardless of method. Real
        // CORS misconfiguration testing happens via ActiveHeaderScanner's own corsProbe battery
        // (synthetic requests with test Origins), not by reading whatever a passively-captured
        // OPTIONS response happened to carry.
        boolean isOptions  = "OPTIONS".equalsIgnoreCase(method);
        // TRACE is stronger than OPTIONS here, not just "not a document", it's a method browsers
        // can never issue in the first place (Fetch spec's forbidden-method list, alongside
        // CONNECT/TRACK), no fetch()/XHR/navigation/CORS preflight ever sends one. So literally
        // none of a TRACE echo response's headers describe anything a real browser will ever act
        // on: not XFO/CSP (nothing renders it), not HSTS (no browser-issued request to enforce
        // it on), not CORS (no browser request exists to gate), not cookie flags (this is
        // Quimera's own probe request/response, not real traffic). Only information disclosure
        // survives, same carve-out as OPTIONS, for the same reason (a leaked Server/tech header
        // is real regardless of what method elicited the response that carried it). The actual
        // TRACE/XST vulnerability itself is a separate ACTIVE finding from ActiveHeaderScanner's
        // own traceProbe, entirely independent of this passive header re-analysis.
        boolean isTrace    = "TRACE".equalsIgnoreCase(method);

        findings.removeIf(f -> {
            String h = f.headerName.toLowerCase(Locale.ROOT);

            if (isOptions || isTrace) {
                // Allow is specifically a capability response header and remains meaningful on
                // OPTIONS. Its passive TRACE result is informational; the active probe decides
                // whether TRACE actually echoes request data.
                if (isOptions && "HTTP TRACE method enabled".equals(f.issueName)) return false;
                return f.category != HeaderFinding.Category.INFORMATION_DISCLOSURE;
            }

            // Server-Timing is useful on real application responses, but gateways/frameworks
            // commonly emit it on every response. Scanner-generated 404/415/500 findings are
            // noise and do not describe the application's normal behaviour.
            if (h.equals("server-timing") && isError) return true;

            // HSTS is transport-layer, meaningful on nearly any real HTTPS response, including
            // assets/API responses/redirects (unlike CSP/XFO's document-only relevance below), so
            // it deliberately does NOT join the asset/API/redirect suppression group further down.
            // It's still emptied out on genuinely uninformative response types though: a 204/304
            // (isEmpty) carries no real headers to judge by definition, and a 4xx/5xx error page
            // (isError, which already covers 401/407 auth challenges too since they're >=400) is
            // one WAF/gateway/app-error response among however many were probed, not evidence the
            // origin's real pages lack HSTS, same "not the real document" reasoning as every other
            // check below. A site that's genuinely missing HSTS everywhere still gets flagged
            // correctly from its actual 200/300 responses, this only stops a 404/405/500 hit
            // during scanning from piling on a duplicate "Missing HSTS" for the same underlying gap.
            if (h.equals("strict-transport-security")) return isEmpty || isError;

            // Information-disclosure and cookie-flag findings leak real information
            // regardless of what's being served. Dropping them for JS/CSS/image responses,
            // redirects, auth challenges or API responses used to be a false-negative bug: a
            // Server/X-Powered-By header or an insecure Set-Cookie doesn't stop being a finding
            // just because the resource happens to be a .js bundle or a 302 redirect.
            // Last-Modified is intentionally included: it is a real observed disclosure and the
            // host-level Report must not lose it merely because it was seen on an asset, redirect,
            // API response or other non-document representation.
            if (f.category == HeaderFinding.Category.INFORMATION_DISCLOSURE
                    || f.category == HeaderFinding.Category.COOKIE) return false;

            // Empty/not-modified responses (204/304): no body at all, nothing else to evaluate
            if (isEmpty) return true;

            // Cross-origin CORS headers on pure static assets (fonts, images, CSS, JS bundles,
            // generic binary downloads) are standard, often REQUIRED practice, cross-origin
            // webfont loading needs Access-Control-Allow-Origin, CDN-hosted assets routinely set
            // it too, that's not a misconfiguration, flagging it here was pure noise. Still
            // flagged normally on HTML/API/auth/redirect responses, exactly where a broken CORS
            // policy can actually expose sensitive, user-specific data. Doesn't affect the
            // ActiveHeaderScanner's live Origin-reflection findings (Category.ACTIVE), those are
            // added after this filter runs and matter regardless of content-type, a server that
            // actually reflects an attacker's Origin back has a real validation bug either way.
            boolean corsHeader = h.equals("access-control-allow-origin")
                    || h.equals("access-control-allow-credentials")
                    || h.equals("timing-allow-origin");
            if (corsHeader && isAsset) return true;

            // Cache-Control on pure static assets: public caching is the CORRECT, often required
            // configuration there (that's the whole point of a CDN-hosted image/font/JS bundle),
            // not a misconfiguration. The rule's real rationale ("this response might carry
            // user-specific or sensitive data that shouldn't be shared-cached") structurally
            // cannot apply to a static asset. Also excluded on error pages (404/405/5xx/...): an
            // error page is not the real document/data the app is meant to serve, "might this get
            // cached and leak sensitive data" doesn't apply to a stock error body either. On
            // surviving HTML/API responses, applyMimeAndCacheContext later requires a concrete
            // sensitivity signal before the missing-header finding is kept.
            if (h.equals("cache-control") && (isAsset || isError || isRedirect)) return true;

            // Error pages never need a MIME-sniffing finding. For successful responses the finer
            // pass later uses Sec-Fetch-Dest, URL extension and MIME type to keep this only for
            // script/style or genuinely ambiguous response contexts.
            if (h.equals("x-content-type-options")) return isError || isRedirect;

            // Document-level browser policies: meaningful only for an actual browsing context
            // (a rendered HTML document), not a fetch()'d JSON blob or an image/font/JS byte
            // stream. Referrer-Policy/COOP/COEP joined this group on the same reasoning already
            // applied to XFO/CSP/Permissions-Policy: none of these mean anything unless something
            // is being navigated to or rendered as a document. Cross-Origin-Resource-Policy is
            // deliberately NOT in this group, it protects THIS resource from being embedded/read
            // cross-origin, so it's if anything MORE relevant on assets/API responses, suppressing
            // it there would be backwards.
            boolean browserRenderingHeader = h.equals("x-frame-options")
                    || h.equals("content-security-policy")
                    || f.category == HeaderFinding.Category.CSP
                    || h.equals("permissions-policy")
                    || h.equals("referrer-policy")
                    || h.equals("cross-origin-opener-policy")
                    || h.equals("cross-origin-embedder-policy")
                    || h.equals("x-xss-protection");

            // 401/407 auth challenges, redirects, error pages, static assets (JS/CSS/images/
            // fonts/binary) and JSON/XML/plain-text API responses: none of these are rendered as
            // a framable HTML document, so framing/CSP/feature-policy findings don't apply, but
            // only those, not the header's mere presence.
            if (isAuth || isAsset || isApi || isRedirect || isError) return browserRenderingHeader;

            // text/html or unknown content type: keep everything
            return false;
        });
    }

    public UrlAnalysisResult analyze(String rawUrl, Map<String, String> headers) {
        String normalizedUrl = normalizeUrl(rawUrl);
        String host          = extractHost(rawUrl);
        String path          = extractPath(rawUrl);

        Map<String, String> ci = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        ci.putAll(headers);

        List<HeaderFinding> findings = new ArrayList<>();

        for (HeaderRule rule : ruleStore.effectiveRules()) {
            // HTTP optional whitespace (OWS) around a header value is not significant, but is
            // still literally present in the raw value string. Trimming it here means anchored
            // exclusion regexes like Server's known-CDN NO_MATCH list (^(?:cloudflare|...)$) still
            // recognise "cloudflare" whether or not the origin/proxy added a trailing space -
            // otherwise the untrimmed value breaks the anchor and the CDN gets misreported as an
            // unrecognised "technology family disclosure".
            String value = ci.get(rule.headerName);
            if (value != null) value = value.trim();
            boolean blank = value != null && value.isBlank();

            // HSTS is meaningless on a plain-HTTP response: browsers ignore a Strict-Transport-
            // Security header entirely unless it arrives over HTTPS (RFC 6797 §7.2), so "add this
            // header" isn't even the right fix for an HTTP-only endpoint, "migrate to HTTPS" is.
            // Flagging it here was misleading advice on every plain-HTTP response; the real gap
            // (content served over plaintext HTTP without a redirect) is already covered by
            // ActiveHeaderScanner's dedicated hstsProbe.
            boolean hstsOnPlainHttp = rule.headerName.equalsIgnoreCase("Strict-Transport-Security")
                    && !normalizedUrl.toLowerCase(Locale.ROOT).startsWith("https://");

            // Missing mandatory header. A present-but-blank value counts as missing too: an empty
            // CSP/HSTS/etc provides exactly as little protection as no header at all, so silently
            // skipping it (old behaviour: value != null, so the "missing" branch never ran, and no
            // value check matched anything meaningful either) was a false negative, not a real pass.
            if (rule.mandatory && (value == null || blank) && rule.missingIssueName != null && !hstsOnPlainHttp) {
                findings.add(new HeaderFinding(
                        rule.missingIssueName,
                        rule.headerName, null,
                        rule.missingDescription,
                        blank ? "Header '" + rule.headerName + "' present but empty."
                              : "Header '" + rule.headerName + "' not found in response.",
                        rule.missingSeverity, rule.missingConfidence, rule.missingCategory,
                        rule.missingReferenceUrl));
                continue;
            }

            // A present-but-blank value (non-mandatory rule, or a mandatory rule with no
            // missing-check defined) discloses nothing and satisfies no real configuration.
            // Treat it the same as absent for the value checks below instead of matching it
            // against ".*"-shaped regexes that trivially match an empty string, e.g. an empty
            // "Server:" header would otherwise still fire "technology family disclosure" despite
            // disclosing literally nothing.
            if (value == null || blank) continue;

            for (FieldCheck fc : rule.checks) {
                boolean matches = safeMatch(fc.regex, value);
                boolean trigger = (fc.triggerOn == FieldCheck.TriggerOn.MATCH && matches)
                               || (fc.triggerOn == FieldCheck.TriggerOn.NO_MATCH && !matches);
                if (trigger) {
                    String evidence = fc.triggerOn == FieldCheck.TriggerOn.MATCH
                            ? rule.headerName + ": " + value
                            : "Header '" + rule.headerName + "' present with value: " + value;
                    findings.add(new HeaderFinding(
                            fc.issueName, rule.headerName, value,
                            fc.description, evidence,
                            fc.severity, fc.confidence, fc.category, fc.referenceUrl));
                }
            }
        }

        // Suppress XFO "missing" when CSP already defines frame-ancestors (XFO is redundant)
        String cspForFrameCheck = ci.get("Content-Security-Policy");
        if (CspAnalyzer.hasDirective(cspForFrameCheck, "frame-ancestors")) {
            findings.removeIf(f -> "Missing Clickjacking Protection".equals(f.issueName));
        }

        // Deep CSP analysis
        String csp   = ci.get("Content-Security-Policy");
        String cspRO = ci.get("Content-Security-Policy-Report-Only");
        findings.addAll(CspAnalyzer.analyze(csp));
        String xfo = ci.get("X-Frame-Options");
        if (xfo != null && xfo.trim().matches("(?i)DENY|SAMEORIGIN")) {
            // A valid XFO already enforces clickjacking protection. Reporting that CSP lacks the
            // equivalent frame-ancestors directive would duplicate a mitigated issue.
            findings.removeIf(f -> "CSP: frame-ancestors directive missing".equals(f.issueName));
        }
        HeaderFinding referrerPolicyFinding = analyzeReferrerPolicy(ci.get("Referrer-Policy"));
        if (referrerPolicyFinding != null) findings.add(referrerPolicyFinding);

        // CSP-Report-Only present but no enforcing CSP: policy is completely unenforced
        if (csp == null && cspRO != null) {
            findings.add(new HeaderFinding(
                "Content-Security-Policy-Report-Only present but CSP not enforced",
                "Content-Security-Policy-Report-Only",
                cspRO,
                "A Content-Security-Policy-Report-Only header is set but there is no enforcing " +
                "Content-Security-Policy header. In report-only mode the browser logs violations " +
                "but does NOT block anything, attackers can fully execute XSS payloads that the " +
                "policy would otherwise block. Deploy the policy as an enforcing Content-Security-Policy.",
                "Content-Security-Policy absent; Content-Security-Policy-Report-Only: " + cspRO,
                // Category.CSP, not SECURITY_MISCONFIGURED: this is a CSP-enforcement finding like
                // every other CspAnalyzer output, applyContextFilter's browserRenderingHeader group
                // keys off Category.CSP to drop CSP findings on 4xx/5xx/redirect/asset/API responses
                // (a policy gap is meaningless where nothing is being rendered as a document), and
                // SECURITY_MISCONFIGURED skipped that gate entirely, reporting it on every error page.
                Severity.MEDIUM, Confidence.CERTAIN, Category.CSP));
            // Also run deep analysis on the CSPO so the user can see the policy quality
            findings.addAll(CspAnalyzer.analyze(cspRO));
        }

        // A deprecated CSP variant (X-Content-Security-Policy / X-WebKit-CSP) present with no real
        // enforcing Content-Security-Policy: the per-header FieldCheck rules for these already say
        // "if this is the only CSP header, there is NO enforced CSP" in their description text, but
        // never escalated severity for that specific scenario, same shape of gap as the
        // CSP-Report-Only case just above. Needs cross-header state (is a REAL CSP also present?),
        // so it lives here rather than in a single-header FieldCheck.
        String xcsp = ci.get("X-Content-Security-Policy");
        String xWebkitCsp = ci.get("X-WebKit-CSP");
        if (csp == null && (xcsp != null || xWebkitCsp != null)) {
            String deprecatedHeader = xcsp != null ? "X-Content-Security-Policy" : "X-WebKit-CSP";
            String deprecatedValue  = xcsp != null ? xcsp : xWebkitCsp;
            findings.add(new HeaderFinding(
                "No enforced CSP (only a deprecated CSP variant present)",
                deprecatedHeader,
                deprecatedValue,
                "'" + deprecatedHeader + "' is present but is a deprecated, non-standard CSP header that " +
                "modern browsers ignore entirely. There is no standard 'Content-Security-Policy' header on " +
                "this response, meaning this application has effectively NO enforced Content Security Policy, " +
                "the deprecated header provides zero real protection. Replace it with a standard " +
                "'Content-Security-Policy' header.",
                "Content-Security-Policy absent; " + deprecatedHeader + ": " + deprecatedValue,
                // Category.CSP for the same reason as the CSP-Report-Only finding above: this is a
                // CSP-enforcement gap, not a generic misconfiguration, and needs the same
                // browserRenderingHeader gating (no CSP findings on error/redirect/asset/API/auth
                // responses, nothing there is being rendered as a document).
                Severity.MEDIUM, Confidence.CERTAIN, Category.CSP));
        }

        // Cookie security flag analysis
        CookiesAndAuthConfig cookiesAndAuthConfig = settings.cookiesAndAuthConfig();
        String setCookieHeader = ci.get("Set-Cookie");
        findings.addAll(CookieAnalyzer.analyze(setCookieHeader, host, cookiesAndAuthConfig));
        recordCookieNamesSeen(host, setCookieHeader);
        findings.addAll(cookieConsistency.observe(rawUrl, setCookieHeader, cookiesAndAuthConfig));

        findings.sort(Comparator.comparingInt(f -> f.severity.order));

        List<TechFinding> techFindings = TechFingerprinter.analyze(ci);

        return new UrlAnalysisResult(normalizedUrl, host, path, findings, headers, techFindings);
    }

    /** Returns only policies that explicitly weaken the modern browser default. Unknown tokens
     * are ignored and the last recognised token wins, matching the Referrer Policy processing
     * model. Absence or no recognised token falls back to strict-origin-when-cross-origin. */
    public static HeaderFinding analyzeReferrerPolicy(String value) {
        if (value == null || value.isBlank()) return null;
        String effective = null;
        for (String token : value.replace('\n', ',').split(",")) {
            String candidate = token.trim().toLowerCase(Locale.ROOT);
            if (REFERRER_POLICIES.contains(candidate)) effective = candidate;
        }
        if (effective == null) return null;
        if (effective.equals("unsafe-url")) {
            return new HeaderFinding(
                    "Referrer-Policy set to unsafe-url", "Referrer-Policy", value,
                    "The effective Referrer-Policy is 'unsafe-url'. It sends the full URL, including " +
                    "path and query string, on same-origin and cross-origin requests and does not suppress " +
                    "the referrer on HTTPS-to-HTTP downgrades.",
                    "Effective policy after processing the fallback list: unsafe-url.",
                    Severity.MEDIUM, Confidence.CERTAIN, Category.SECURITY_MISCONFIGURED,
                    "https://w3c.github.io/webappsec-referrer-policy/#referrer-policy-unsafe-url");
        }
        if (effective.equals("no-referrer-when-downgrade")) {
            return new HeaderFinding(
                    "Referrer-Policy exposes full URLs cross-origin", "Referrer-Policy", value,
                    "The effective 'no-referrer-when-downgrade' policy sends the full source URL to " +
                    "cross-origin HTTPS destinations. This is weaker than the modern default, which sends " +
                    "only the origin cross-site, and can disclose sensitive path or query data.",
                    "Effective policy after processing the fallback list: no-referrer-when-downgrade.",
                    Severity.LOW, Confidence.CERTAIN, Category.SECURITY_MISCONFIGURED,
                    "https://w3c.github.io/webappsec-referrer-policy/#referrer-policy-no-referrer-when-downgrade");
        }
        return null;
    }

    // ------ URL helpers ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

    public static String normalizeUrl(String rawUrl) {
        try {
            URI u = URI.create(rawUrl);
            if (u.getScheme() == null || u.getHost() == null) return rawUrl;
            String path = u.getPath();
            if (path == null || path.isEmpty()) path = "/";
            int port = u.getPort();
            String portStr = (port > 0 && port != 80 && port != 443) ? ":" + port : "";
            return u.getScheme() + "://" + u.getHost() + portStr + path;
        } catch (IllegalArgumentException e) { return rawUrl; }
    }

    public static String extractHost(String rawUrl) {
        try {
            String host = URI.create(rawUrl).getHost();
            return host == null ? rawUrl : host;
        } catch (IllegalArgumentException e) { return rawUrl; }
    }

    public static String extractPath(String rawUrl) {
        try {
            String p = URI.create(rawUrl).getPath();
            return (p == null || p.isEmpty()) ? "/" : p;
        } catch (IllegalArgumentException e) { return "/"; }
    }

    private static boolean safeMatch(String regex, String value) {
        Optional<Pattern> cached = PATTERN_CACHE.computeIfAbsent(regex, k -> {
            try { return Optional.of(Pattern.compile(k)); }
            catch (PatternSyntaxException e) { return Optional.empty(); }
        });
        return cached.isPresent() && cached.get().matcher(value).find();
    }
}
