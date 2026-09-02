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
import com.b3xal.headeranalyzer.util.SafeLogging;

import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;

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
    private static final String LABEL_CORS_PROBE  = "CORS probe";
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
        if (settings.isActiveScanOptionsProbe()) {
            try {
                out.addAll(corsProbe(baseUrl, template));
            } catch (Exception ex) {
                SafeLogging.error(api, "[Quimera] Active CORS probe error: " + ex.getMessage());
            }
        }
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
        if (probeLabel.startsWith(LABEL_CORS_PROBE + ": ")) {
            return retestCorsRequestOnly(probeLabel, url, template);
        }
        if (probeLabel.equals(LABEL_TRACE_PROBE)) return traceProbe(url);
        if (probeLabel.equals(LABEL_HSTS_PROBE))  return hstsProbe(url);
        return null;
    }

    /** Whether a label belongs to a probe this scanner can explicitly reproduce. A supported
     * retest may legitimately return null when the issue is no longer present; callers must not
     * mistake that for an unknown label and silently fall back to passive analysis. */
    public static boolean supportsRetestLabel(String probeLabel) {
        return probeLabel != null && (probeLabel.startsWith(LABEL_CORS_PROBE + ": ")
                || probeLabel.equals(LABEL_TRACE_PROBE)
                || probeLabel.equals(LABEL_HSTS_PROBE));
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
    private UrlAnalysisResult retestCorsRequestOnly(String probeLabel, String url, HttpRequest originalReq) {
        HttpRequestResponse rr = api.http().sendRequest(originalReq);
        if (rr == null || rr.response() == null) return null;

        Map<String, String> headerMap = collectHeaders(rr);
        UrlAnalysisResult result = engine.analyze(url, headerMap, rr.response().statusCode(),
                rr.response().bodyToString(), rr.request().method());
        result = tag(result, rr, probeLabel);

        var originHeader = originalReq.header("Origin");
        String testOrigin = originHeader != null ? originHeader.value() : PROBE_ORIGIN;

        List<HeaderFinding> extra = new ArrayList<>();
        String issueName = probeLabel.substring((LABEL_CORS_PROBE + ": ").length());
        checkReflection(headerMap, rr.response().statusCode(), testOrigin, extra, issueName,
                "The server again reflected the exact tested Origin (" + testOrigin + ") in " +
                "Access-Control-Allow-Origin.");
        return result.withReplacedFindings(extra);
    }

    private interface ProbeCall { UrlAnalysisResult run() throws Exception; }

    private void safeAdd(List<UrlAnalysisResult> out, ProbeCall call) {
        try {
            UrlAnalysisResult r = call.run();
            if (r != null) out.add(r);
        } catch (Exception ex) {
            SafeLogging.error(api, "[Quimera] Active scan probe error: " + ex.getMessage());
        }
    }

    // ------ CORS Origin-reflection battery ------------------------------------------------------------------------------------------------------------------------------
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

    private List<UrlAnalysisResult> corsProbe(String url, HttpRequest template) {
        List<UrlAnalysisResult> results = new ArrayList<>();
        // A successful preflight only grants permission to attempt the real request. It does not
        // prove that the actual endpoint returns readable data, so never turn an observed OPTIONS
        // exchange itself into a confirmed CORS finding.
        if (template != null && "OPTIONS".equalsIgnoreCase(template.method())) return results;
        HttpRequestResponse baseRr = sendWithOrigin(url, template, PROBE_ORIGIN);
        if (baseRr == null || baseRr.response() == null) return results;

        Map<String, String> headerMap = collectHeaders(baseRr);
        UrlAnalysisResult result = engine.analyze(url, headerMap, baseRr.response().statusCode(),
                baseRr.response().bodyToString(), baseRr.request().method());
        result = tag(result, baseRr, corsLabel("CORS reflects arbitrary Origin"));

        List<HeaderFinding> extra = new ArrayList<>();

        // Test 1: arbitrary reflection, no origin validation at all.
        checkReflection(headerMap, baseRr.response().statusCode(), PROBE_ORIGIN, extra,
                "CORS reflects arbitrary Origin",
                "The server reflected an arbitrary, attacker-chosen Origin (" + PROBE_ORIGIN + ") back in " +
                "Access-Control-Allow-Origin instead of validating it against an allow-list.");
        result = result.withExtraFindings(extra);
        if (!extra.isEmpty()) results.add(result);

        String host = extractHost(url);
        if (host != null && !host.isBlank()) {
            // Test 2: HTTP downgrade, does the server trust its own origin sent over plain HTTP?
            String downgradeOrigin = httpDowngradeOrigin(url);
            if (downgradeOrigin != null) {
                addOriginProbe(results, url, template, downgradeOrigin,
                        "CORS trusts own origin sent over plaintext HTTP",
                        "The server reflected its own origin (" + host + ") even when it arrived over plain HTTP " +
                        "instead of HTTPS. If an attacker can get a victim onto an HTTP page on any network path " +
                        "(coffee-shop Wi-Fi, ISP injection), that page can make authenticated cross-origin requests " +
                        "as if it were the real HTTPS origin.");
            }

            // Test 3: null origin, exploitable via sandboxed iframes and some redirect chains.
            addOriginProbe(results, url, template, "null",
                    "CORS reflects the null Origin",
                    "The server reflected the literal 'null' Origin, which browsers send from sandboxed iframes " +
                    "(<iframe sandbox>), data: URLs, and some redirect chains. An attacker can trivially cause " +
                    "a browser to send Origin: null and make cross-origin requests that this server accepts.",
                    REF_CORS_NULL_ORIGIN);

            boolean domainHost = isDomainHost(host);
            // Domain-validation variants do not make sense for localhost or IP literals.
            if (domainHost) {
                // Test 4: prefix bypass, unanchored startsWith()/regex matching "target.attacker.com".
                addOriginProbe(results, url, template, "https://" + host + "." + PROBE_DOMAIN,
                    "CORS Origin validation bypassed via subdomain-suffix trick",
                    "The server reflected an Origin of the form 'https://" + host + "." + PROBE_DOMAIN + "', " +
                    "an attacker-registered domain that merely starts with the real hostname. This indicates " +
                    "the validation logic checks a prefix (e.g. startsWith() or an unanchored regex) instead of " +
                    "the full, exact origin, any domain the attacker owns that begins with '" + host + ".' passes.",
                    REF_CORS_PREFIX_SUFFIX_BYPASS);

            // Test 5: suffix/concatenation bypass, unanchored endsWith()/contains().
            addOriginProbe(results, url, template, concatenationBypassOrigin(host),
                    "CORS Origin validation bypassed via domain-concatenation trick",
                    "The server reflected an Origin of the form 'https://" + host + PROBE_DOMAIN + "', an " +
                    "attacker-registered domain that merely ends with or contains the real hostname. This " +
                    "indicates the validation logic checks a suffix (e.g. endsWith()/contains()) without " +
                    "anchoring on a domain boundary.",
                    REF_CORS_PREFIX_SUFFIX_BYPASS);

            // Test 6: arbitrary trusted subdomain, no verification that the subdomain is real/owned.
            addOriginProbe(results, url, template, fakeSubdomainOrigin(host),
                    "CORS trusts arbitrary subdomains of the real origin",
                    "The server reflected an Origin on an arbitrary, made-up subdomain ('random-quimera." + host +
                    "') that was never verified to exist or be owned by the same team. If any subdomain of " +
                    host + " is vulnerable to takeover or hosts attacker-controlled/user-generated content, " +
                    "this CORS policy extends trust to it.");

            if (host.length() > 1) {
                // Test 7: truncated host, off-by-one in prefix-length validation.
                String truncated = host.substring(0, host.length() - 1);
                addOriginProbe(results, url, template, "https://" + truncated,
                        "CORS Origin validation has an off-by-one truncation bug",
                        "The server reflected an Origin ('https://" + truncated + "') that is the real hostname " +
                        "with its last character removed. This is a strong indicator of an off-by-one error in " +
                        "prefix-length validation logic.");
            }

            if (host.chars().filter(ch -> ch == '.').count() > 1) {
                // Test 8: dot-to-x, catches validation regexes where "." was not escaped to "\.".
                int lastDot = host.lastIndexOf('.');
                String dotless = host.substring(0, lastDot).replace(".", "x") + host.substring(lastDot);
                addOriginProbe(results, url, template, "https://" + dotless,
                        "CORS Origin validation regex does not escape the dot metacharacter",
                        "The server reflected an Origin ('https://" + dotless + "') where dots before the " +
                        "registrable-domain boundary were replaced with 'x'. This only reflects if validation uses a " +
                        "regular expression where the literal dot was left unescaped, in regex syntax an " +
                        "unescaped '.' matches any character, so 'wwwxexample.com' incorrectly matches a " +
                        "pattern meant for 'www.example.com'.",
                        "https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/CORS%20Misconfiguration/README.md");

                // Test 9: underscore-concatenation bypass (corben.io "advanced-cors-techniques"),
                // present in additional-cors-checks' own current test battery, added here for parity.
                addOriginProbe(results, url, template, "https://" + host + "_" + PROBE_DOMAIN,
                        "CORS Origin validation bypassed via underscore-concatenation trick",
                        "The server reflected an Origin of the form 'https://" + host + "_" + PROBE_DOMAIN + "', " +
                        "an attacker-registered domain formed by appending an underscore directly after the real " +
                        "hostname with no separating dot. Some origin-validation logic incorrectly treats '_' as " +
                        "a safe domain-boundary character, this indicates that class of bug.",
                        "https://corben.io/blog/18-6-16-advanced-cors-techniques");
                }
            }
        }

        return results;
    }

    /** Builds the request for one Origin-battery test. When a captured template is available, that
     * exact request (method, body, headers, cookies included) is replayed with only Origin swapped
     * in, for any verb, the most accurate signal of what a real browser would get, and what a
     * server actually does on the real method rather than on OPTIONS. Only falls back to a
     * synthetic GET when there is no captured request to replay at all (e.g. a manually-typed
     * URL Quimera never saw traffic for). A preflight response alone is not enough to prove the
     * actual response is readable, so the fallback deliberately does not use OPTIONS. */
    private HttpRequestResponse sendWithOrigin(String url, HttpRequest template, String origin) {
        if (template != null) {
            return api.http().sendRequest(template.withHeader("Origin", origin));
        }
        HttpRequest req = HttpRequest.httpRequestFromUrl(url)
                .withMethod("GET")
                .withAddedHeader("Origin", origin);
        return api.http().sendRequest(req);
    }

    private static String corsLabel(String issueName) {
        return LABEL_CORS_PROBE + ": " + issueName;
    }

    /** Sends one Origin-battery variant and, only when that exact value is reflected, stores a
     * separate result backed by the exact request/response pair. Keeping each positive separate
     * prevents Burp's HTTP viewer from showing the baseline arbitrary-Origin request while the
     * selected finding actually came from a subdomain/null/regex-bypass request. */
    private void addOriginProbe(List<UrlAnalysisResult> results, String url, HttpRequest template,
                                String testOrigin, String issueName, String bugDescription) {
        addOriginProbe(results, url, template, testOrigin, issueName, bugDescription, null);
    }

    private void addOriginProbe(List<UrlAnalysisResult> results, String url, HttpRequest template,
                                String testOrigin, String issueName, String bugDescription,
                                String referenceUrl) {
        try {
            HttpRequestResponse rr = sendWithOrigin(url, template, testOrigin);
            if (rr == null || rr.response() == null) return;
            List<HeaderFinding> findings = new ArrayList<>();
            checkReflection(collectHeaders(rr), rr.response().statusCode(), testOrigin,
                    findings, issueName, bugDescription, referenceUrl);
            if (!findings.isEmpty()) {
                results.add(probeResult(url, rr, findings, corsLabel(issueName)));
            }
        } catch (Exception ex) {
            SafeLogging.error(api, "[Quimera] CORS origin-variant probe error: " + ex.getMessage());
        }
    }

    private UrlAnalysisResult probeResult(String url, HttpRequestResponse rr,
                                           List<HeaderFinding> findings, String label) {
        Map<String, String> headers = collectHeaders(rr);
        UrlAnalysisResult result = engine.analyze(url, headers, rr.response().statusCode(),
                rr.response().bodyToString(), rr.request().method()).withReplacedFindings(findings);
        return tag(result, rr, label);
    }

    /** If Access-Control-Allow-Origin echoes testOrigin back, records a finding for it. */
    static void checkReflection(Map<String, String> headerMap, int statusCode, String testOrigin,
                                List<HeaderFinding> extra, String issueName, String bugDescription) {
        checkReflection(headerMap, statusCode, testOrigin, extra, issueName, bugDescription, null);
    }

    private static void checkReflection(Map<String, String> headerMap, int statusCode, String testOrigin,
                                         List<HeaderFinding> extra, String issueName, String bugDescription,
                                         String referenceUrl) {
        // Reflection on 401/403/404/405/5xx (or a bodyless 204) is only policy/header behaviour,
        // not confirmation that attacker-readable endpoint data was returned. ACAC handling below
        // remains unchanged for genuine 2xx confirmations.
        if (statusCode < 200 || statusCode >= 300 || statusCode == 204) return;
        String acao = headerMap.getOrDefault("Access-Control-Allow-Origin", null);
        if (acao == null || !acao.trim().equalsIgnoreCase(testOrigin.trim())) return;

        String acac  = headerMap.getOrDefault("Access-Control-Allow-Credentials", "");
        boolean creds = acac.trim().equalsIgnoreCase("true");
        String vary = headerMap.getOrDefault("Vary", "");
        boolean variesOnOrigin = Arrays.stream(vary.split(","))
                .anyMatch(v -> v.trim().equalsIgnoreCase("Origin") || v.trim().equals("*"));
        String varyEvidence = "  |  Vary: " + (vary.isBlank() ? "(absent)" : vary);
        String varyContext = variesOnOrigin ? "" :
                " The response also lacks Vary: Origin (or Vary: *). This does not create the " +
                "reflection flaw—the arbitrary Origin is already accepted directly—but should be fixed " +
                "to prevent origin-specific responses being mixed by shared caches.";

        findingsAdd(extra,
                issueName + (creds ? " with credentials allowed" : ""),
                "Access-Control-Allow-Origin",
                "Origin: " + testOrigin + "  ->  Access-Control-Allow-Origin: " + acao
                        + (creds ? "  |  Access-Control-Allow-Credentials: true" : "")
                        + varyEvidence,
                bugDescription + " " + (creds
                    ? "Combined with Access-Control-Allow-Credentials: true, any page matching this pattern " +
                      "can make authenticated cross-origin requests (with cookies) and read the response, " +
                      "this is a full CORS-based account takeover / data theft primitive."
                    : "Any page matching this pattern can read this endpoint's response cross-origin, a " +
                      "confidentiality risk if the response contains sensitive or user-specific data.")
                        + varyContext,
                creds ? Severity.HIGH : Severity.LOW,
                creds ? Confidence.CERTAIN : Confidence.FIRM, referenceUrl);
    }

    private static String extractHost(String url) {
        try {
            return URI.create(url).getHost();
        } catch (Exception ex) {
            return null;
        }
    }

    static String httpDowngradeOrigin(String url) {
        try {
            URI uri = URI.create(url);
            if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null) return null;
            String host = uri.getHost().contains(":") ? "[" + uri.getHost() + "]" : uri.getHost();
            return "http://" + host;
        } catch (Exception ex) {
            return null;
        }
    }

    static boolean isDomainHost(String host) {
        if (host == null || host.equalsIgnoreCase("localhost") || host.contains(":")) return false;
        return !host.matches("\\d{1,3}(?:\\.\\d{1,3}){3}") && host.contains(".");
    }

    static String concatenationBypassOrigin(String host) {
        return "https://" + host + PROBE_DOMAIN;
    }

    static String fakeSubdomainOrigin(String host) {
        return "https://random-quimera." + host;
    }

    // ------ TRACE / Cross-Site Tracing probe ------------------------------------------------------------------------------------------------------------------------

    private UrlAnalysisResult traceProbe(String url) {
        String marker = UUID.randomUUID().toString();
        HttpRequest req = HttpRequest.httpRequestFromUrl(url).withMethod("TRACE")
                .withUpdatedHeader("X-Quimera-Trace-Probe", marker);
        HttpRequestResponse rr = api.http().sendRequest(req);
        if (rr.response() == null) return null;

        String body = rr.response().bodyToString();
        int status = rr.response().statusCode();
        if (status < 200 || status >= 300 || !isGenuineTraceEcho(body, marker)) return null;

        Map<String, String> headerMap = collectHeaders(rr);
        UrlAnalysisResult result = engine.analyze(url, headerMap, status, body, rr.request().method());
        List<HeaderFinding> findings = new ArrayList<>();
        findingsAdd(findings, "TRACE method enabled (request echoed by server)",
                "(request method)", "TRACE " + url + ", HTTP " + status +
                        ", X-Quimera-Trace-Probe marker echoed: " + marker,
                "The server returned a genuine TRACE response: both the TRACE request line and a unique " +
                        "Quimera-controlled request header were echoed in the response body. This can expose " +
                        "request headers to Cross-Site Tracing attacks in clients capable of issuing TRACE. " +
                        "Disable the TRACE method.",
                Severity.MEDIUM, Confidence.CERTAIN,
                "https://owasp.org/www-community/attacks/Cross_Site_Tracing");
        return tag(result.withReplacedFindings(findings), rr, LABEL_TRACE_PROBE);
    }

    static boolean isGenuineTraceEcho(String body, String marker) {
        if (body == null || marker == null || marker.isBlank()) return false;
        boolean requestLine = Pattern.compile("(?im)^TRACE\\s+\\S+\\s+HTTP/\\d(?:\\.\\d)?\\s*$")
                .matcher(body).find();
        boolean markerHeader = Pattern.compile("(?im)^X-Quimera-Trace-Probe:\\s*"
                + Pattern.quote(marker) + "\\s*$").matcher(body).find();
        return requestLine && markerHeader;
    }

    // ------ HTTP → HTTPS downgrade / HSTS enforcement probe ---------------------------------------------------------------------------

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

    // ------ Shared helpers ------------------------------------------------------------------------------------------------------------------------------------------------------------------------

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
