package com.b3xal.headeranalyzer.analyzer;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.b3xal.headeranalyzer.config.QuimeraSettings;
import com.b3xal.headeranalyzer.model.Confidence;
import com.b3xal.headeranalyzer.model.HeaderFinding;
import com.b3xal.headeranalyzer.model.HeaderFinding.Category;
import com.b3xal.headeranalyzer.model.Severity;
import com.b3xal.headeranalyzer.model.UrlAnalysisResult;

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Active header analysis: sends real requests to a single endpoint to reveal behaviour that
 * passive header reading cannot, a battery of Origin-reflection CORS tests (replaying the real
 * captured request when available, see {@link #corsProbe}), a TRACE / Cross-Site-Tracing probe,
 * and an HTTP→HTTPS downgrade check to see whether HSTS is actually enforced rather than merely
 * advertised.
 *
 * Each probe that gets a response becomes its own {@link UrlAnalysisResult} (tagged with a
 * probeLabel) so it shows up in the Logger like any other captured URL, with the dynamic finding
 * (if any) merged into the normal rule-based findings for that response.
 */
public class ActiveHeaderScanner {

    private static final String PROBE_ORIGIN = "https://quimera-cors-probe.invalid";
    private static final String PROBE_DOMAIN = "quimera-cors-probe.invalid";

    // Advisory-pane "want to dig deeper?" links (see HeaderFinding#referenceUrl), only for the
    // couple of bypass tests below with a real, verified writeup covering that EXACT technique,
    // not a generic CORS page for every test in the battery.
    private static final String REF_CORS_NULL_ORIGIN = "https://portswigger.net/web-security/cors";
    private static final String REF_CORS_PREFIX_SUFFIX_BYPASS =
            "https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties";

    // probeLabel constants, shared between tag() call sites below and retest() so a rename in one
    // place can't silently break the other's string match.
    private static final String LABEL_CORS_PROBE  = "CORS probe (Origin reflection)";
    private static final String LABEL_TRACE_PROBE = "TRACE probe (XST)";
    private static final String LABEL_HSTS_PROBE  = "HSTS probe (HTTP→HTTPS)";

    private final MontoyaApi api;
    private final HeaderAnalysisEngine engine;
    private final QuimeraSettings settings;

    public ActiveHeaderScanner(MontoyaApi api, HeaderAnalysisEngine engine, QuimeraSettings settings) {
        this.api      = api;
        this.engine   = engine;
        this.settings = settings;
    }

    /** Runs every enabled probe against baseUrl, with no captured original request to replay
     * (synthetic requests only, see {@link #scan(String, HttpRequest)}). Never throws, failures
     * are logged and skipped. */
    public List<UrlAnalysisResult> scan(String baseUrl) {
        return scan(baseUrl, null);
    }

    /** Same as {@link #scan(String)}, but when the caller has the original captured request
     * (real method, headers, cookies) for this URL, the CORS Origin battery replays THAT exact
     * request with only the Origin header swapped, instead of a bare synthetic one, see
     * {@link #corsProbe} for why that matters. template may be null (falls back to synthetic). */
    public List<UrlAnalysisResult> scan(String baseUrl, HttpRequest template) {
        List<UrlAnalysisResult> out = new ArrayList<>();
        if (settings.isActiveScanOptionsProbe()) safeAdd(out, () -> corsProbe(baseUrl, template));
        if (settings.isActiveScanTraceProbe())   safeAdd(out, () -> traceProbe(baseUrl));
        if (settings.isActiveScanHstsProbe())    safeAdd(out, () -> hstsProbe(baseUrl));
        return out;
    }

    /** Re-runs whichever specific probe originally produced this result, matched by its
     * probeLabel. Used by DetailPanel's Retest button on a probe row: a plain passive
     * re-analysis (engine.analyze()) has no knowledge of Category.ACTIVE findings at all, those
     * come entirely from this class's own status/body inspection (checkReflection, the TRACE
     * echo check, the redirect check), not the FieldCheck rule engine, so retesting a probe row
     * through the passive path silently dropped every active finding instead of re-verifying it.
     * Returns null for a non-probe row (probeLabel == null) or an unrecognised label, callers
     * should fall back to a plain passive re-analysis in that case. Runs regardless of whether
     * the matching activeScan*Probe setting is currently enabled, an explicit Retest click is an
     * intentional one-off action, not the auto-scan path those settings gate. */
    public UrlAnalysisResult retest(String probeLabel, String url, HttpRequest template) {
        if (probeLabel == null) return null;
        // CORS deliberately does NOT re-run corsProbe() (the full ~10-request origin-bypass
        // battery) here, see retestCorsRequestOnly: a Retest click on one row should resend
        // only the one request the analyst is looking at, not fire a fresh battery at the target.
        if (probeLabel.equals(LABEL_CORS_PROBE))  return retestCorsRequestOnly(url, template);
        if (probeLabel.equals(LABEL_TRACE_PROBE)) return traceProbe(url);
        if (probeLabel.equals(LABEL_HSTS_PROBE))  return hstsProbe(url);
        return null;
    }

    /** Scoped CORS retest: replays ONLY the exact request originally captured for this row
     * (always the PROBE_ORIGIN baseline test, see corsProbe's baseRr) instead of the full
     * origin-bypass battery, and re-verifies just the "arbitrary Origin reflection" finding that
     * specific request/response pair represents. The battery's OTHER bypass-specific findings
     * that may be bundled into the same Logger row (null origin, subdomain-suffix, HTTP
     * downgrade, TRACE-via-preflight, ...) each came from a DIFFERENT request this method never
     * re-sends, so they are not re-verified by Retest, only a fresh "Active header scan" covers
     * those. testOrigin is read back from the request itself (its actual Origin header) rather
     * than assuming PROBE_ORIGIN, so this stays correct even if corsProbe's baseline test ever
     * changes what Origin it sends. */
    private UrlAnalysisResult retestCorsRequestOnly(String url, HttpRequest originalReq) {
        HttpRequestResponse rr = api.http().sendRequest(originalReq);
        if (rr == null || rr.response() == null) return null;

        Map<String, String> headerMap = collectHeaders(rr);
        UrlAnalysisResult result = engine.analyze(url, headerMap, rr.response().statusCode(),
                rr.response().bodyToString(), rr.request().method());
        result = tag(result, rr, LABEL_CORS_PROBE);

        var originHeader = originalReq.header("Origin");
        String testOrigin = originHeader != null ? originHeader.value() : PROBE_ORIGIN;

        List<HeaderFinding> extra = new ArrayList<>();
        checkReflection(headerMap, testOrigin, extra,
                "CORS reflects arbitrary Origin",
                "The server reflected an arbitrary, attacker-chosen Origin (" + testOrigin + ") back in " +
                "Access-Control-Allow-Origin instead of validating it against an allow-list.");
        return result.withExtraFindings(extra);
    }

    private interface ProbeCall { UrlAnalysisResult run() throws Exception; }

    private void safeAdd(List<UrlAnalysisResult> out, ProbeCall call) {
        try {
            UrlAnalysisResult r = call.run();
            if (r != null) out.add(r);
        } catch (Exception ex) {
            api.logging().logToError("[Quimera] Active scan probe error: " + ex.getMessage());
        }
    }

    // ── CORS Origin-reflection battery ──────────────────────────────────────────
    //
    // Adapted from the test methodology of PortSwigger's additional-cors-checks extension
    // (read from its CorsHelper.kt source, reimplemented here rather than copied), plus two
    // deliberate improvements over it:
    //
    //  1) Real-request replay instead of OPTIONS-only. additional-cors-checks clones the exact
    //     proxied request (method, headers, cookies) and only swaps Origin, then reads the CORS
    //     headers off the REAL response, not a synthetic OPTIONS, an explicit design choice in
    //     their own code (CorsHelper.evaluateColor bails out entirely when the request is OPTIONS).
    //     That matters for two reasons: (a) some backends only set permissive CORS headers on the
    //     preflight and are stricter on the actual response (or vice-versa), testing OPTIONS-only
    //     both misses and over-reports; (b) most GETs are "simple requests", browsers never
    //     preflight them at all, so the OPTIONS response can be entirely irrelevant to what a
    //     browser actually gets. When Quimera has the original captured request (from a Logger
    //     row or sitemap entry) for a GET/HEAD, it now replays THAT exact request (same method,
    //     headers, cookies) with only Origin swapped, see {@link #sendWithOrigin}. This also fixes
    //     a real false-negative: many CORS-reflection bugs only trigger for an authenticated
    //     (cookie-bearing) request in the first place, a cookie-less synthetic probe would get a
    //     different, non-vulnerable code path and miss the bug entirely.
    //  2) Full parity with additional-cors-checks on method handling, by explicit choice: when a
    //     captured request is available, it is replayed exactly (method, body, headers, cookies)
    //     for EVERY verb, not just GET/HEAD, same as the reference extension does. A POST/PUT/
    //     PATCH/DELETE gets replayed once per test origin (up to 9 times), which can re-trigger a
    //     real, state-changing action against the target if the endpoint is mutating, that's the
    //     tradeoff for not missing CORS bugs that only manifest on the real verb (some backends
    //     only validate/reflect Origin on the actual method, not on OPTIONS). This only runs when
    //     the caller explicitly opted into active probing in the first place (manual "Active
    //     header scan", bulk active scan, or the Auto Active Scan toggle), never silently.
    //
    // Every origin that gets reflected back in Access-Control-Allow-Origin produces its own
    // finding with a distinct issue name, so the evidence text alone tells the analyst exactly
    // which validation bug is present.

    private UrlAnalysisResult corsProbe(String url, HttpRequest template) {
        HttpRequestResponse baseRr = sendWithOrigin(url, template, PROBE_ORIGIN);
        if (baseRr == null || baseRr.response() == null) return null;

        Map<String, String> headerMap = collectHeaders(baseRr);
        UrlAnalysisResult result = engine.analyze(url, headerMap, baseRr.response().statusCode(),
                baseRr.response().bodyToString(), baseRr.request().method());
        result = tag(result, baseRr, LABEL_CORS_PROBE);

        List<HeaderFinding> extra = new ArrayList<>();

        // Test 1: arbitrary reflection, no origin validation at all.
        checkReflection(headerMap, PROBE_ORIGIN, extra,
                "CORS reflects arbitrary Origin",
                "The server reflected an arbitrary, attacker-chosen Origin (" + PROBE_ORIGIN + ") back in " +
                "Access-Control-Allow-Origin instead of validating it against an allow-list.");

        // Access-Control-Allow-Methods/TRACE only ever appears on an actual preflight response,
        // a real-request replay of a GET would never carry it even if the server would happily
        // advertise TRACE, so this is always its own dedicated OPTIONS request regardless of
        // whether the main battery above used real-request replay or not.
        HttpRequestResponse preflightRr = sendOptionsPreflight(url, PROBE_ORIGIN,
                template != null ? template.method() : "GET");
        if (preflightRr != null && preflightRr.response() != null) {
            String allow = collectHeaders(preflightRr).getOrDefault("Access-Control-Allow-Methods", "");
            if (allow.toUpperCase().contains("TRACE")) {
                findingsAdd(extra, "TRACE method advertised via CORS (Access-Control-Allow-Methods)",
                        "Access-Control-Allow-Methods", "Access-Control-Allow-Methods: " + allow,
                        "The OPTIONS preflight response advertises TRACE as an allowed method, which can " +
                        "facilitate Cross-Site Tracing (XST) attacks. Remove TRACE from allowed methods.",
                        Severity.LOW, Confidence.CERTAIN, "https://owasp.org/www-community/attacks/Cross_Site_Tracing");
            }
        }

        String host = extractHost(url);
        if (host != null && !host.isBlank()) {
            // Test 2: HTTP downgrade, does the server trust its own origin sent over plain HTTP?
            testOrigin(url, template, "http://" + host, extra,
                    "CORS trusts own origin sent over plaintext HTTP",
                    "The server reflected its own origin (" + host + ") even when it arrived over plain HTTP " +
                    "instead of HTTPS. If an attacker can get a victim onto an HTTP page on any network path " +
                    "(coffee-shop Wi-Fi, ISP injection), that page can make authenticated cross-origin requests " +
                    "as if it were the real HTTPS origin.");

            // Test 3: null origin, exploitable via sandboxed iframes and some redirect chains.
            testOrigin(url, template, "null", extra,
                    "CORS reflects the null Origin",
                    "The server reflected the literal 'null' Origin, which browsers send from sandboxed iframes " +
                    "(<iframe sandbox>), data: URLs, and some redirect chains. An attacker can trivially cause " +
                    "a browser to send Origin: null and make cross-origin requests that this server accepts.",
                    REF_CORS_NULL_ORIGIN);

            // Test 4: prefix bypass, unanchored startsWith()/regex matching "target.attacker.com".
            testOrigin(url, template, "https://" + host + "." + PROBE_DOMAIN, extra,
                    "CORS Origin validation bypassed via subdomain-suffix trick",
                    "The server reflected an Origin of the form 'https://" + host + "." + PROBE_DOMAIN + "', " +
                    "an attacker-registered domain that merely starts with the real hostname. This indicates " +
                    "the validation logic checks a prefix (e.g. startsWith() or an unanchored regex) instead of " +
                    "the full, exact origin, any domain the attacker owns that begins with '" + host + ".' passes.",
                    REF_CORS_PREFIX_SUFFIX_BYPASS);

            // Test 5: suffix/concatenation bypass, unanchored endsWith()/contains().
            testOrigin(url, template, "https://" + PROBE_DOMAIN + host, extra,
                    "CORS Origin validation bypassed via domain-concatenation trick",
                    "The server reflected an Origin of the form 'https://" + PROBE_DOMAIN + host + "', an " +
                    "attacker-registered domain that merely ends with or contains the real hostname. This " +
                    "indicates the validation logic checks a suffix (e.g. endsWith()/contains()) without " +
                    "anchoring on a domain boundary.",
                    REF_CORS_PREFIX_SUFFIX_BYPASS);

            // Test 6: arbitrary trusted subdomain, no verification that the subdomain is real/owned.
            testOrigin(url, template, "https://random-quimera." + host, extra,
                    "CORS trusts arbitrary subdomains of the real origin",
                    "The server reflected an Origin on an arbitrary, made-up subdomain ('random-quimera." + host +
                    "') that was never verified to exist or be owned by the same team. If any subdomain of " +
                    host + " is vulnerable to takeover or hosts attacker-controlled/user-generated content, " +
                    "this CORS policy extends trust to it.");

            if (host.length() > 1) {
                // Test 7: truncated host, off-by-one in prefix-length validation.
                String truncated = host.substring(0, host.length() - 1);
                testOrigin(url, template, "https://" + truncated, extra,
                        "CORS Origin validation has an off-by-one truncation bug",
                        "The server reflected an Origin ('https://" + truncated + "') that is the real hostname " +
                        "with its last character removed. This is a strong indicator of an off-by-one error in " +
                        "prefix-length validation logic.");
            }

            if (host.contains(".")) {
                // Test 8: dot-to-x, catches validation regexes where "." was not escaped to "\.".
                String dotless = host.replace(".", "x");
                testOrigin(url, template, "https://" + dotless, extra,
                        "CORS Origin validation regex does not escape the dot metacharacter",
                        "The server reflected an Origin ('https://" + dotless + "') where every '.' in the real " +
                        "hostname was replaced with 'x'. This only reflects if the validation logic uses a " +
                        "regular expression where the literal dot was left unescaped, in regex syntax an " +
                        "unescaped '.' matches any character, so 'examplexcom' incorrectly matches a pattern " +
                        "meant for 'example.com'.",
                        "https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/CORS%20Misconfiguration/README.md");

                // Test 9: underscore-concatenation bypass (corben.io "advanced-cors-techniques"),
                // present in additional-cors-checks' own current test battery, added here for parity.
                testOrigin(url, template, "https://" + host + "_" + PROBE_DOMAIN, extra,
                        "CORS Origin validation bypassed via underscore-concatenation trick",
                        "The server reflected an Origin of the form 'https://" + host + "_" + PROBE_DOMAIN + "', " +
                        "an attacker-registered domain formed by appending an underscore directly after the real " +
                        "hostname with no separating dot. Some origin-validation logic incorrectly treats '_' as " +
                        "a safe domain-boundary character, this indicates that class of bug.",
                        "https://corben.io/blog/18-6-16-advanced-cors-techniques");
            }
        }

        return result.withExtraFindings(extra);
    }

    /** Builds the request for one Origin-battery test. When a captured template is available, that
     * exact request (method, body, headers, cookies included) is replayed with only Origin swapped
     * in, for any verb, the most accurate signal of what a real browser would get, and what a
     * server actually does on the real method rather than on OPTIONS. Only falls back to a
     * synthetic OPTIONS preflight when there is no captured request to replay at all (e.g. a
     * manually-typed URL Quimera never saw traffic for). */
    private HttpRequestResponse sendWithOrigin(String url, HttpRequest template, String origin) {
        if (template != null) {
            return api.http().sendRequest(template.withHeader("Origin", origin));
        }
        return sendOptionsPreflight(url, origin, "GET");
    }

    private HttpRequestResponse sendOptionsPreflight(String url, String origin, String requestMethod) {
        HttpRequest req = HttpRequest.httpRequestFromUrl(url)
                .withMethod("OPTIONS")
                .withAddedHeader("Origin", origin)
                .withAddedHeader("Access-Control-Request-Method", requestMethod)
                .withAddedHeader("Access-Control-Request-Headers", "X-Quimera-Probe");
        return api.http().sendRequest(req);
    }

    /** Sends one Origin-battery test (real-request replay or synthetic preflight, see
     * {@link #sendWithOrigin}) and checks for reflection. */
    private void testOrigin(String url, HttpRequest template, String testOrigin, List<HeaderFinding> extra,
                             String issueName, String bugDescription) {
        testOrigin(url, template, testOrigin, extra, issueName, bugDescription, null);
    }

    private void testOrigin(String url, HttpRequest template, String testOrigin, List<HeaderFinding> extra,
                             String issueName, String bugDescription, String referenceUrl) {
        try {
            HttpRequestResponse rr = sendWithOrigin(url, template, testOrigin);
            if (rr == null || rr.response() == null) return;
            checkReflection(collectHeaders(rr), testOrigin, extra, issueName, bugDescription, referenceUrl);
        } catch (Exception ex) {
            api.logging().logToError("[Quimera] CORS origin-variant probe error: " + ex.getMessage());
        }
    }

    /** If Access-Control-Allow-Origin echoes testOrigin back, records a finding for it. */
    private static void checkReflection(Map<String, String> headerMap, String testOrigin,
                                         List<HeaderFinding> extra, String issueName, String bugDescription) {
        checkReflection(headerMap, testOrigin, extra, issueName, bugDescription, null);
    }

    private static void checkReflection(Map<String, String> headerMap, String testOrigin,
                                         List<HeaderFinding> extra, String issueName, String bugDescription,
                                         String referenceUrl) {
        String acao = headerMap.getOrDefault("Access-Control-Allow-Origin", null);
        if (acao == null || !acao.trim().equalsIgnoreCase(testOrigin.trim())) return;

        String acac  = headerMap.getOrDefault("Access-Control-Allow-Credentials", "");
        boolean creds = acac.trim().equalsIgnoreCase("true");

        findingsAdd(extra,
                issueName + (creds ? " with credentials allowed" : ""),
                "Access-Control-Allow-Origin",
                "Origin: " + testOrigin + "  ->  Access-Control-Allow-Origin: " + acao
                        + (creds ? "  |  Access-Control-Allow-Credentials: true" : ""),
                bugDescription + " " + (creds
                    ? "Combined with Access-Control-Allow-Credentials: true, any page matching this pattern " +
                      "can make authenticated cross-origin requests (with cookies) and read the response, " +
                      "this is a full CORS-based account takeover / data theft primitive."
                    : "Any page matching this pattern can read this endpoint's response cross-origin, a " +
                      "confidentiality risk if the response contains sensitive or user-specific data."),
                creds ? Severity.HIGH : Severity.MEDIUM, Confidence.CERTAIN, referenceUrl);
    }

    private static String extractHost(String url) {
        try {
            return URI.create(url).getHost();
        } catch (Exception ex) {
            return null;
        }
    }

    // ── TRACE / Cross-Site Tracing probe ────────────────────────────────────────

    private UrlAnalysisResult traceProbe(String url) {
        HttpRequest req = HttpRequest.httpRequestFromUrl(url).withMethod("TRACE");
        HttpRequestResponse rr = api.http().sendRequest(req);
        if (rr.response() == null) return null;

        Map<String, String> headerMap = collectHeaders(rr);
        String body = rr.response().bodyToString();
        UrlAnalysisResult result = engine.analyze(url, headerMap, rr.response().statusCode(), body, rr.request().method());
        result = tag(result, rr, LABEL_TRACE_PROBE);

        List<HeaderFinding> extra = new ArrayList<>();
        int status = rr.response().statusCode();
        boolean echoed = body != null && body.contains("TRACE ");

        if (status >= 200 && status < 300 && (echoed || !body.isBlank())) {
            findingsAdd(extra, "TRACE method enabled (server responded to TRACE)",
                    "(request method)", "TRACE " + url + "  →  HTTP " + status,
                    "The server accepted a TRACE request and returned a " + status + " response" +
                    (echoed ? " that echoes the original request back verbatim" : "") +
                    ". If a browser can be made to issue TRACE requests (via plugins/XHR in older browsers), " +
                    "this can be combined with XSS to read HttpOnly cookies and other headers " +
                    "otherwise inaccessible to JavaScript (Cross-Site Tracing). Disable the TRACE method.",
                    Severity.MEDIUM, Confidence.FIRM, "https://owasp.org/www-community/attacks/Cross_Site_Tracing");
        }
        return result.withExtraFindings(extra);
    }

    // ── HTTP → HTTPS downgrade / HSTS enforcement probe ─────────────────────────

    private UrlAnalysisResult hstsProbe(String url) {
        if (!url.toLowerCase().startsWith("https://")) return null; // only meaningful starting from https
        String httpUrl = "http://" + url.substring("https://".length());

        HttpRequest req = HttpRequest.httpRequestFromUrl(httpUrl);
        HttpRequestResponse rr = api.http().sendRequest(req);
        if (rr.response() == null) return null;

        Map<String, String> headerMap = collectHeaders(rr);
        UrlAnalysisResult result = engine.analyze(httpUrl, headerMap, rr.response().statusCode(),
                rr.response().bodyToString(), rr.request().method());
        result = tag(result, rr, LABEL_HSTS_PROBE);

        List<HeaderFinding> extra = new ArrayList<>();
        int status = rr.response().statusCode();
        String location = headerMap.getOrDefault("Location", "");
        boolean redirectsToHttps = status >= 300 && status < 400 && location.toLowerCase().startsWith("https://");

        // An error status (4xx/5xx) here is inconclusive noise, not a hardening gap: it's just as
        // likely to be a WAF/load-balancer actively REJECTING plaintext HTTP (some deliberately
        // 400/403 on port 80 instead of redirecting, which is arguably GOOD behaviour, not a
        // finding), or a generic error page unrelated to whether HTTPS is really enforced, as it
        // is a genuine missing-redirect gap. Only fire when the response is otherwise a normal
        // 2xx/3xx that isn't a clean redirect to HTTPS, where "does this actually protect the
        // user" has a real, unambiguous answer.
        if (!redirectsToHttps && status < 400) {
            boolean servedContent = status >= 200 && status < 300;
            findingsAdd(extra,
                    servedContent
                        ? "Plaintext HTTP serves content instead of redirecting to HTTPS"
                        : "Plaintext HTTP does not redirect to HTTPS",
                    "(protocol)",
                    "GET " + httpUrl + "  →  HTTP " + status +
                            (location.isEmpty() ? "" : "  |  Location: " + location),
                    servedContent
                        ? "The site responded to a plain HTTP request with a " + status + " response " +
                          "instead of redirecting to HTTPS, meaning the content was actually served over an " +
                          "unencrypted connection, an attacker on the network path can read or tamper with it " +
                          "on this first request, before any HSTS policy from a prior HTTPS visit can apply."
                        : "The site did not respond with an HTTP→HTTPS redirect (got " + status + "). " +
                          "Without an explicit redirect, a user's first request (or a stripped link) can stay " +
                          "on plaintext HTTP even if an HSTS header is present on the HTTPS site.",
                    // Categorically different severities: servedContent means the actual application
                    // response was exposed in cleartext on this request (direct MITM read/tamper on
                    // real content, C:H/I:H). The no-redirect-no-content case exposes nothing on
                    // THIS response, it's a hardening gap (a future request might still be caught),
                    // not an active content exposure, hence the lower LOW/FIRM instead of MEDIUM.
                    servedContent ? Severity.MEDIUM : Severity.LOW,
                    servedContent ? Confidence.CERTAIN : Confidence.FIRM);
        }
        return result.withExtraFindings(extra);
    }

    // ── Shared helpers ────────────────────────────────────────────────────────

    private static Map<String, String> collectHeaders(HttpRequestResponse rr) {
        Map<String, String> headerMap = new LinkedHashMap<>();
        rr.response().headers().forEach(h ->
                com.b3xal.headeranalyzer.util.HeaderMaps.addResponse(headerMap, h.name(), h.value()));
        return headerMap;
    }

    private static UrlAnalysisResult tag(UrlAnalysisResult result, HttpRequestResponse rr, String probeLabel) {
        try {
            result.rawRequest  = rr.request().toString();
            result.rawResponse = rr.response().toString();
        } catch (Exception ignored) {}
        result.method          = rr.request() != null ? rr.request().method() : null;
        result.statusCode      = rr.response() != null ? rr.response().statusCode() : -1;
        result.contentLength   = rr.response() != null ? rr.response().body().length() : -1;
        result.probeLabel       = probeLabel;
        result.originalRequest  = rr.request();
        result.originalResponse = rr.response();
        return result;
    }

    private static void findingsAdd(List<HeaderFinding> list, String issue, String header,
                                     String evidence, String description, Severity sev, Confidence conf) {
        findingsAdd(list, issue, header, evidence, description, sev, conf, null);
    }

    private static void findingsAdd(List<HeaderFinding> list, String issue, String header,
                                     String evidence, String description, Severity sev, Confidence conf,
                                     String referenceUrl) {
        list.add(new HeaderFinding(issue, header, evidence, description, evidence, sev, conf, Category.ACTIVE, referenceUrl));
    }
}
