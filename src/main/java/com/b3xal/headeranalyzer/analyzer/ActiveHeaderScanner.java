package com.b3xal.headeranalyzer.analyzer;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.b3xal.headeranalyzer.config.QuimeraSettings;
import com.b3xal.headeranalyzer.model.Confidence;
import com.b3xal.headeranalyzer.model.HeaderFinding;
import com.b3xal.headeranalyzer.model.HeaderFinding.Category;
import com.b3xal.headeranalyzer.model.Severity;
import com.b3xal.headeranalyzer.model.UrlAnalysisResult;
import com.b3xal.headeranalyzer.util.SafeLogging;
import com.b3xal.headeranalyzer.util.ThrottledRequestSender;

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
    private static final String LABEL_WEBDAV_PROBE = "WebDAV probe (OPTIONS)";
    private static final String LABEL_CACHE_PROBE = "Cache/CDN debug disclosure probe";
    private static final List<String> CACHE_DEBUG_PRAGMA_TOKENS = List.of(
            // PortSwigger labs and several proxy integrations require this exact literal value.
            "x-get-cache-key", "x-get-true-cache-key",
            "akamai-x-get-cache-key", "akamai-x-get-true-cache-key",
            // Akamai's own documented debug directives beyond the cache key itself (confirmed
            // against techdocs.akamai.com/edge-diagnostics/docs/pragma-headers and
            // techdocs.akamai.com/property-mgr/reference/debug-variables): extracted-values/nonces
            // make Akamai echo back the live value of every declared property variable in
            // X-Akamai-Session-Info (internal origin hostnames, feature flags, ... whatever the
            // property happens to put in a variable), and check-cacheable discloses the
            // cacheability decision itself. Variables default to hidden/sensitive, so a real value
            // showing up here means that protection was explicitly turned off, i.e. this is a
            // genuine disclosure when it fires, not spec-technically-possible noise.
            "akamai-x-get-extracted-values", "akamai-x-get-nonces", "akamai-x-check-cacheable");
    // A response served straight from a shared cache never runs the origin's diagnostic-header
    // logic for our Pragma token, it just replays whatever was already stored, so hitting a HIT
    // here would make a real disclosure look like the app never echoes cache-key headers. Retries
    // are capped so a permanently warm cache (buster ignored, TTL never short enough) can't hang
    // the probe forever; five retries at the requested cadence is roughly two and a half minutes
    // per Pragma token, which is acceptable for an explicit active-scan probe.
    private static final int CACHE_BUSTER_MAX_RETRIES = 5;
    private static final long CACHE_BUSTER_RETRY_DELAY_MS = 30_000L;

    private final MontoyaApi api;
    private final HeaderAnalysisEngine engine;
    private final QuimeraSettings settings;
    // Set once on extension unload (see #shutdown). The cache-key buster discovery loop is the one
    // place in this class that can legitimately still be mid-retry, asleep for up to 30s, when a
    // reload happens; without this check that thread wakes up and calls the now-invalid MontoyaApi
    // anyway, which Burp reports as a stack of NullPointerExceptions in Errors even though
    // SafeLogging already swallows them, purely cosmetic but worth not doing at all.
    private volatile boolean shuttingDown = false;

    // Routes every probe request in this class through Burp's own project-configured resource
    // pool (Project options / Resource Pool / Default), the same one Scanner and Live Tasks draw
    // on, instead of firing at whatever rate this class's callers happen to schedule work at. See
    // ThrottledRequestSender's own javadoc for the Community Edition fallback.
    private final ThrottledRequestSender sender;

    public ActiveHeaderScanner(MontoyaApi api, HeaderAnalysisEngine engine, QuimeraSettings settings) {
        this.api      = api;
        this.engine   = engine;
        this.settings = settings;
        this.sender   = new ThrottledRequestSender(api, "Quimera - Active header probes");
    }

    /** Called from {@code QuimeraHttpHandler.shutdown()} on extension unload/reload. */
    public void shutdown() {
        shuttingDown = true;
        sender.shutdown();
    }

    /** Lets other classes that already hold a reference to this scanner (BulkAnalyzer, the manual
     * "Retest" action in DetailPanel/ReportPanel) send their own one-off evidence-refresh requests
     * through the same throttled sender instead of each keeping (and having to shut down) their
     * own separate resource-pool engine for what is fundamentally the same kind of request. */
    public HttpRequestResponse sendThrottled(HttpRequest request) {
        return sender.send(request);
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
        return scan(baseUrl, template, null);
    }

    /** Allows auto/bulk scan callers to supply the already-observed baseline exchange (the real,
     * un-probed traffic Quimera already captured for this URL). If that response was an explicit
     * cache MISS, a single clean identical replay can confirm MISS->HIT, see
     * {@link #cacheKeyDisclosureProbe} for why this must be the real exchange and not just its
     * headers: the confirmation needs a real HttpRequestResponse pair to attach as evidence. */
    public List<UrlAnalysisResult> scan(String baseUrl, HttpRequest template,
                                        HttpRequestResponse initialExchange) {
        List<UrlAnalysisResult> out = new ArrayList<>();
        out.addAll(scanCacheKey(baseUrl, template, initialExchange));
        out.addAll(scanNonCacheProbes(baseUrl, template));
        return out;
    }

    /** Runs only the cheap cache-key probe. Kept separate so automatic scanning can put it on a
     * dedicated queue and guarantee coverage for every observed URL without waiting behind the
     * much larger CORS battery. */
    public List<UrlAnalysisResult> scanCacheKey(String baseUrl, HttpRequest template,
                                                 HttpRequestResponse initialExchange) {
        List<UrlAnalysisResult> out = new ArrayList<>();
        safeAdd(out, () -> cacheKeyDisclosureProbe(baseUrl, template, initialExchange));
        return out;
    }

    /** Runs the remaining, heavier active-header probes. */
    public List<UrlAnalysisResult> scanNonCacheProbes(String baseUrl, HttpRequest template) {
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
        if (settings.isActiveScanWebDavProbe())  safeAdd(out, () -> webDavProbe(baseUrl));
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
        if (probeLabel.equals(LABEL_WEBDAV_PROBE)) return webDavProbe(url);
        if (probeLabel.equals(LABEL_CACHE_PROBE)) return cacheKeyDisclosureProbe(url, template, null);
        return null;
    }

    /** Whether a label belongs to a probe this scanner can explicitly reproduce. A supported
     * retest may legitimately return null when the issue is no longer present; callers must not
     * mistake that for an unknown label and silently fall back to passive analysis. */
    public static boolean supportsRetestLabel(String probeLabel) {
        return probeLabel != null && (probeLabel.startsWith(LABEL_CORS_PROBE + ": ")
                || probeLabel.equals(LABEL_TRACE_PROBE)
                || probeLabel.equals(LABEL_HSTS_PROBE)
                || probeLabel.equals(LABEL_WEBDAV_PROBE)
                || probeLabel.equals(LABEL_CACHE_PROBE));
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
        HttpRequestResponse rr = sender.send(originalReq);
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
            return sender.send(template.withHeader("Origin", origin));
        }
        HttpRequest req = HttpRequest.httpRequestFromUrl(url)
                .withMethod("GET")
                .withAddedHeader("Origin", origin);
        return sender.send(req);
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
        HttpRequestResponse rr = sender.send(req);
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

    // ------ Cache/CDN debug disclosure probe ----------------------------------------------------------

    /** Builds one cache-debug replay: template's real method/headers/cookies with the given
     * Pragma value substituted in (or a synthetic GET when there is no captured template), plus the
     * non-Pragma debug headers every attempt carries regardless of which Pragma token is used. */
    static HttpRequest buildCacheDebugRequest(String url, HttpRequest template, String pragmaValue) {
        if (template != null) {
            // Deliberately replace (rather than merge) an existing Pragma. Browsers commonly
            // capture requests with "Pragma: no-cache"; appending our token would turn an
            // isolated attempt into "no-cache, x-get-cache-key" and strict/naive cache-debug
            // handlers would not recognise it. The original template is immutable, so every
            // attempt still starts from the untouched captured request.
            HttpRequest safeGet = template.withMethod("GET").withBody("")
                    .withRemovedHeader("Content-Length")
                    .withRemovedHeader("Transfer-Encoding")
                    .withRemovedHeader("If-None-Match")
                    .withRemovedHeader("If-Modified-Since")
                    .withRemovedHeader("Range")
                    .withRemovedHeader("Upgrade")
                    .withRemovedHeader("Connection")
                    .withRemovedHeader("Sec-WebSocket-Key")
                    .withRemovedHeader("Sec-WebSocket-Version")
                    .withRemovedHeader("Sec-WebSocket-Extensions")
                    .withRemovedHeader("Sec-WebSocket-Protocol")
                    // Remove first, then use withHeader (Montoya's documented "add or update")
                    // below, not withUpdatedHeader: that method's own javadoc only promises to
                    // "update the value of an existing header", with no documented guarantee it
                    // adds one that isn't there, unlike withHeader's explicit "if the header
                    // doesn't exist, it is added". Most captured templates for ordinary
                    // subresource fetches (images, CSS, JS) never carry a Pragma at all, only
                    // top-level navigations sometimes do, so relying on "update" alone silently
                    // sent the debug requests with NO Pragma header for most real traffic, always
                    // returning a plain response with no diagnostic evidence.
                    .withRemovedHeader("Pragma");
            return safeGet.withHeader("Pragma", pragmaValue)
                    .withHeader("Akamai-Debug", "cache")
                    .withHeader("Fastly-Debug", "1")
                    .withHeader("X-Cache-Debug", "1")
                    .withHeader("X-Debug", ATS_XDEBUG_VALUE);
        }
        return HttpRequest.httpRequestFromUrl(url).withMethod("GET")
                .withAddedHeader("Pragma", pragmaValue)
                .withAddedHeader("Akamai-Debug", "cache")
                .withAddedHeader("Fastly-Debug", "1")
                .withAddedHeader("X-Cache-Debug", "1")
                .withAddedHeader("X-Debug", ATS_XDEBUG_VALUE);
    }

    // Apache Traffic Server's built-in xdebug plugin (confirmed against
    // docs.trafficserver.apache.org/.../plugins/xdebug.en.html): present on the request, it
    // injects exactly the debug headers named in its (comma-separated) value into the response.
    // "Probe" and "Diags" are deliberately excluded: Probe dumps every request/response header
    // into the response BODY and disables writing to cache (a real side effect on the exchange,
    // not just extra headers), and Diags only enables server-side log verbosity, no response
    // header of its own to detect. ATS is already a known CDN identity in KnownInfrastructure.
    private static final String ATS_XDEBUG_VALUE = "X-Cache-Key,X-Cache,X-ParentSelection-Key,X-Remap,Via";

    /** One injection point a cache buster can live in, mirroring where Param Miner
     * (https://github.com/portswigger/param-miner) looks for unkeyed/keyed input: the query
     * string, a cookie, or a header. Which one (if any) a given cache actually partitions on is
     * never known up front, and guessing wrong silently produces the exact "no evidence" result a
     * strict cache ignoring the buster would, indistinguishable from "this app never echoes the
     * key at all". */
    private enum CacheBusterChannel { QUERY, COOKIE, HEADER }
    private static final List<CacheBusterChannel> CACHE_BUSTER_CHANNELS =
            List.of(CacheBusterChannel.QUERY, CacheBusterChannel.COOKIE, CacheBusterChannel.HEADER);

    /** Per-host memory of whichever channel already proved it changes this host's cache key, so
     * every URL on that host after the first tries the known-good channel first instead of
     * re-running the full discovery sequence every single time. */
    private final Map<String, CacheBusterChannel> confirmedBusterChannelByHost = new java.util.concurrent.ConcurrentHashMap<>();

    private static HttpRequest applyCacheBuster(HttpRequest req, CacheBusterChannel channel, String value) {
        return switch (channel) {
            case QUERY -> req.withAddedParameters(HttpParameter.urlParameter("quimera_cb", value));
            case COOKIE -> req.withAddedParameters(HttpParameter.cookieParameter("quimera_cb", value));
            case HEADER -> req.withAddedHeader("X-Quimera-Cb", value);
        };
    }

    /** Param Miner's actual technique for confirming a candidate is genuinely part of the cache
     * key, rather than assuming: try it and see whether the response actually changes with it.
     * Every round tries ALL of {@link #CACHE_BUSTER_CHANNELS} back-to-back with no delay between
     * them (whichever channel already proved itself for this host goes first, see
     * {@link #confirmedBusterChannelByHost}) before ever waiting on anything, so a channel that
     * works shows a result almost immediately instead of queuing behind the other two channels'
     * full retry budgets first. Only if EVERY channel in a round comes back an explicit cache HIT
     * (none of them freed a real answer) does it wait out one shared delay and try a fresh round
     * of busters on all channels again, up to {@link #CACHE_BUSTER_MAX_RETRIES} rounds. If a round
     * gets a non-HIT answer (MISS, or no cache signal) from every channel with no disclosure, this
     * app simply never echoes a key here, no amount of waiting will change that, so it stops
     * immediately instead of burning the rest of the retry budget. */
    private HttpRequestResponse discoverCacheKeyViaBusterChannels(String host, String url, HttpRequest template,
                                                                    String pragmaToken) {
        CacheBusterChannel preferred = confirmedBusterChannelByHost.get(host);
        List<CacheBusterChannel> order = new ArrayList<>();
        if (preferred != null) order.add(preferred);
        for (CacheBusterChannel c : CACHE_BUSTER_CHANNELS) if (c != preferred) order.add(c);

        HttpRequestResponse last = null;
        for (int round = 0; round <= CACHE_BUSTER_MAX_RETRIES; round++) {
            if (shuttingDown) return last;
            boolean everyChannelStillHit = true;
            for (CacheBusterChannel channel : order) {
                if (shuttingDown) return last;
                String buster = UUID.randomUUID().toString().replace("-", "").substring(0, 12);
                HttpRequest req = applyCacheBuster(buildCacheDebugRequest(url, template, pragmaToken), channel, buster);
                HttpRequestResponse resp = sender.send(req);
                if (resp == null || resp.response() == null) {
                    last = resp; everyChannelStillHit = false; continue;
                }
                last = resp;
                Map<String, String> respHeaders = collectHeaders(resp);
                boolean disclosed = !cacheKeyDisclosureFindings(respHeaders).isEmpty();
                CacheSignalKind signalKind = explicitCacheSignal(respHeaders).kind;
                if (disclosed) {
                    confirmedBusterChannelByHost.put(host, channel);
                    return resp;
                }
                if (signalKind != CacheSignalKind.HIT) everyChannelStillHit = false;
            }
            if (!everyChannelStillHit) return last;
            if (round == CACHE_BUSTER_MAX_RETRIES) {
                return last;
            }
            try {
                Thread.sleep(CACHE_BUSTER_RETRY_DELAY_MS);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                return last;
            }
        }
        return last;
    }

    /** Requests cache diagnostics through the documented Akamai Pragma directives (cache key,
     * extracted-values/nonces, check-cacheable) plus common opt-in debug headers used by
     * reverse-proxy integrations (Fastly-Debug, generic X-Cache-Debug). Only a literal disclosure
     * response header (cache key, Akamai session-info/check-cacheable, or a Fastly-Debug-* header)
     * on a successful response is a finding; accepting/ignoring a request header proves nothing. */
    private UrlAnalysisResult cacheKeyDisclosureProbe(String url, HttpRequest template,
                                                       HttpRequestResponse initialExchange) {
        List<HeaderFinding> findings = new ArrayList<>();
        HttpRequestResponse displayed = null;
        boolean displayedIsDisclosing = false;
        List<HttpRequestResponse> exchanges = new ArrayList<>();
        List<String> exchangeLabels = new ArrayList<>();

        // Send literal tokens from the outset. A combined first attempt is not harmless: strict
        // implementations ignore it and it can warm the cache with a response that lacks the
        // diagnostic header before the useful request is sent. Also inspect every HTTP status.
        // A cache key disclosed on a redirect/error is still a disclosure; status filtering only
        // belongs to the separate MISS->HIT confirmation below.
        String host = HeaderAnalysisEngine.extractHost(url);
        for (String token : CACHE_DEBUG_PRAGMA_TOKENS) {
            HttpRequestResponse attempt = discoverCacheKeyViaBusterChannels(host, url, template, token);
            if (attempt == null || attempt.response() == null) {
                continue;
            }
            Map<String, String> attemptHeaders = collectHeaders(attempt);
            exchanges.add(attempt);
            exchangeLabels.add("Pragma: " + token + " (HTTP " + attempt.response().statusCode() + ")");
            if (displayed == null) {
                displayed = attempt;
            }
            List<HeaderFinding> attemptFindings = cacheKeyDisclosureFindings(attemptHeaders);
            if (!attemptFindings.isEmpty()) {
                findings.addAll(attemptFindings);
                // Only the FIRST token that actually discloses something becomes the default
                // displayed PoC. Real bug this fixes: with several tokens each producing their
                // own finding (a literal cache key from the plain token, then ALSO an Akamai
                // extracted-values dump from a later one), this used to keep overwriting
                // `displayed` with whichever token happened to run last, so the analyst's default
                // PoC was frequently NOT the request/response that actually showed the disclosure
                // they were looking at, an unrelated later attempt was. Every exchange is still
                // recorded in probeExchanges/probeExchangeLabels either way, so nothing about
                // later disclosures is lost, only which one is shown by default without having to
                // pick from the dropdown.
                if (!displayedIsDisclosing) {
                    displayed = attempt;
                    displayedIsDisclosing = true;
                }
                // Deliberately NOT breaking here: the different Pragma tokens now test
                // independent disclosure families (a literal cache key vs. Akamai's
                // extracted-values/nonces variable dump vs. its check-cacheable decision), not
                // just different spellings of the same request. A hit on an earlier token (e.g.
                // the plain "x-get-cache-key" one) says nothing about whether a later token (e.g.
                // "akamai-x-get-extracted-values") also discloses something, stopping here would
                // silently skip testing it at all. The de-dup pass below still collapses the
                // common case where several tokens surface the exact same header/value into one
                // card, so this only adds genuinely distinct findings, not noise.
            }
        }
        if (displayed == null) return null;

        // ------ Clean (non-busted) MISS->HIT confirmation --------------------------------------
        //
        // Deliberately independent of the Pragma/cache-buster battery above: that battery decorates
        // every request with debug Pragma tokens and unique buster values to surface disclosure, so
        // its own exchanges make misleading "before/after" evidence, an analyst should never see
        // ?quimera_cb=... or Pragma: akamai-x-... in what's supposed to prove ordinary caching
        // behaviour. This confirmation instead replays the EXACT clean request Quimera already
        // observed (or an untouched synthetic GET when there is no captured template) a second
        // time, unmodified, so both attached exchanges read exactly like ordinary browser traffic.
        if (initialExchange != null && initialExchange.response() != null) {
            CacheSignal initialSignal = explicitCacheSignal(collectHeaders(initialExchange));
            if (initialSignal.kind == CacheSignalKind.MISS) {
                // Only ever replay a safe, idempotent GET, same posture as the debug battery
                // above (buildCacheDebugRequest forces GET too): a captured template for a
                // POST/PUT/DELETE must never be resent verbatim just to confirm caching, that
                // would re-trigger a real state-changing action purely as a side effect of this
                // diagnostic. Falls back to a synthetic GET rather than skipping the confirmation
                // entirely, most caches don't key non-GET responses anyway, so a GET against the
                // same URL is still a meaningful, safe check.
                HttpRequest cleanReq = (template != null && "GET".equalsIgnoreCase(template.method()))
                        ? template : HttpRequest.httpRequestFromUrl(url);
                HttpRequestResponse cleanReplay = sender.send(cleanReq);
                if (cleanReplay != null && cleanReplay.response() != null) {
                    int replayStatus = cleanReplay.response().statusCode();
                    if (replayStatus >= 200 && replayStatus < 300 && replayStatus != 204) {
                        HeaderFinding transition = cacheTransitionFinding(
                                collectHeaders(initialExchange), collectHeaders(cleanReplay));
                        if (transition != null) {
                            findings.add(transition);
                            // Position 1 = the clean MISS, position 2 = the clean HIT replay,
                            // ahead of whatever cache-key debug exchanges already queued above:
                            // Burp's native Issue viewer (and Quimera's own exchange selector)
                            // shows probeExchanges in list order, so the analyst sees the actual
                            // before/after pair first, not a page of debug-probe noise.
                            exchanges.add(0, cleanReplay);
                            exchangeLabels.add(0, "Identical clean replay (HIT)");
                            exchanges.add(0, initialExchange);
                            exchangeLabels.add(0, "Baseline (clean, MISS)");
                            // Only claims the default displayed slot if the token loop above found
                            // no actual disclosure to show. Real bug this fixes: this assignment
                            // was unconditional, so on a page where the debug battery ALSO found a
                            // genuine X-Cache-Key disclosure (the more specific, more severe
                            // finding, an analyst most needs to see the exact request/response
                            // that leaked it), this clean MISS/HIT pair silently replaced it as the
                            // default evidence anyway, showing an unrelated clean exchange for a
                            // finding whose own evidence text (correctly) referenced the disclosed
                            // key from the busted/Pragma request. The clean pair is still recorded
                            // in probeExchanges either way, selectable from the dropdown.
                            if (!displayedIsDisclosing) {
                                displayed = cleanReplay;
                                displayedIsDisclosing = true;
                            }
                        }
                    }
                }
            }
        }
        if (findings.isEmpty()) return null;
        // A key exposed on both requests is one disclosure, not two cards.
        findings = new ArrayList<>(findings.stream().collect(java.util.stream.Collectors.toMap(
                HeaderFinding::aggregationKey, f -> f, (a, b) -> a, LinkedHashMap::new)).values());
        UrlAnalysisResult result = probeResult(url, displayed, findings, LABEL_CACHE_PROBE);
        result.probeExchanges = List.copyOf(exchanges);
        result.probeExchangeLabels = List.copyOf(exchangeLabels);
        return result;
    }

    private enum CacheSignalKind { HIT, MISS, NONE }
    private record CacheSignal(CacheSignalKind kind, String headerName, String headerValue, String line) {}

    static HeaderFinding cacheTransitionFinding(Map<String, String> firstHeaders,
                                                 Map<String, String> secondHeaders) {
        CacheSignal initial = explicitCacheSignal(firstHeaders);
        CacheSignal replay = explicitCacheSignal(secondHeaders);
        if (initial.kind != CacheSignalKind.MISS || replay.kind != CacheSignalKind.HIT) return null;
        String evidence = initial.line + "  ->  " + replay.line;
        return new HeaderFinding(
                "Shared cache confirmed by MISS-to-HIT transition",
                replay.headerName, replay.headerValue,
                "Two identical safe requests produced an explicit cache MISS followed by an explicit " +
                        "cache HIT. This confirms that an intermediary or reverse proxy stored and reused " +
                        "the response. It is an informational cache-oracle signal, not proof of cache " +
                        "poisoning or cache deception; test cache keys and handling of personalized content " +
                        "separately.",
                evidence, Severity.INFORMATION, Confidence.CERTAIN,
                Category.INFORMATION_DISCLOSURE,
                "https://www.rfc-editor.org/rfc/rfc9211.html#section-6");
    }

    /** Recognises explicit cache decisions across RFC 9211 and common CDN/proxy formats. */
    private static CacheSignal explicitCacheSignal(Map<String, String> headers) {
        String age = headers.entrySet().stream().filter(e -> e.getKey().equalsIgnoreCase("Age"))
                .map(Map.Entry::getValue).findFirst().orElse(null);
        if (age != null) {
            try {
                if (Long.parseLong(age.trim()) > 3_600L)
                    return new CacheSignal(CacheSignalKind.NONE, "", "", "");
            } catch (NumberFormatException ignored) { }
        }
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            String name = entry.getKey();
            String value = entry.getValue();
            if (value == null || value.isBlank()) continue;
            String n = name.toLowerCase();
            String v = value.trim();
            boolean hit = false;
            boolean miss = false;
            if (n.equals("cache-status")) {
                hit = Pattern.compile("(?i)(?:^|[;,\\s])hit(?:=\\?1)?(?:$|[;,\\s])").matcher(v).find();
                miss = Pattern.compile("(?i)(?:^|[;,\\s])fwd=(?:uri-miss|vary-miss|miss)(?:$|[;,\\s])")
                        .matcher(v).find();
            } else if (n.equals("server-timing")) {
                hit = Pattern.compile("(?i)(?:^|[,\\s])cdn-cache-(?:hit|refresh)(?:$|[;,\\s])").matcher(v).find()
                        || Pattern.compile("(?i)(?:cf)?cache(?:status)?;[^,]*desc=\\\"?(?:hit|stale|updating|revalidated)\\\"?").matcher(v).find();
                miss = Pattern.compile("(?i)(?:^|[,\\s])cdn-cache-miss(?:$|[;,\\s])").matcher(v).find()
                        || Pattern.compile("(?i)(?:cf)?cache(?:status)?;[^,]*desc=\\\"?miss\\\"?").matcher(v).find();
            } else if (n.equals("x-cache") || n.equals("cf-cache-status")
                    || n.equals("cdn-cache-status") || n.equals("x-cache-status")
                    || n.equals("x-proxy-cache") || n.equals("x-proxy-cache-status")
                    || n.equals("x-fastcgi-cache") || n.equals("x-litespeed-cache")
                    || n.equals("x-kinsta-cache") || n.equals("x-drupal-cache")
                    || n.equals("x-varnish-cache")) {
                hit = Pattern.compile("(?i)(?:^|[;,\\s])(?:tcp_(?:mem_)?hit|tcp_refresh_hit|" +
                        "refresh_hit|hit(?:[-_](?:fresh|stale))?|stale|updating|revalidated)(?:$|[;,\\s])")
                        .matcher(v).find();
                miss = Pattern.compile("(?i)(?:^|[;,\\s])(?:tcp_(?:refresh_)?miss|miss)(?:$|[;,\\s])")
                        .matcher(v).find();
            }
            if (hit || miss) return new CacheSignal(hit ? CacheSignalKind.HIT : CacheSignalKind.MISS,
                    name, v, name + ": " + v);
        }
        return new CacheSignal(CacheSignalKind.NONE, "", "", "");
    }

    /** True only when the response contains an explicit cache HIT/MISS oracle. Used to avoid
     * firing cache-key diagnostics at endpoints with no evidence of an intermediary cache. */
    public static boolean hasExplicitCacheSignal(Map<String, String> headers) {
        return headers != null && explicitCacheSignal(headers).kind != CacheSignalKind.NONE;
    }

    /** Broad baseline gate for deciding whether cache diagnostics are relevant. Explicit vendor
     * HIT/MISS headers are strongest, but a valid Age or cacheable Cache-Control response is also
     * enough evidence; requiring one vendor vocabulary caused real cacheable URLs to be skipped. */
    public static boolean hasCacheEvidence(Map<String, String> headers) {
        if (headers == null || headers.isEmpty()) return false;
        if (hasExplicitCacheSignal(headers)) return true;
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            String value = entry.getValue() == null ? "" : entry.getValue().trim();
            if (entry.getKey().equalsIgnoreCase("Age")) {
                try {
                    if (Long.parseLong(value) >= 0) return true;
                } catch (NumberFormatException ignored) { }
            }
            if (entry.getKey().equalsIgnoreCase("Cache-Control")
                    && Pattern.compile("(?i)(?:^|,)\\s*(?:public|s-maxage\\s*=|max-age\\s*=)")
                    .matcher(value).find()) return true;
        }
        return false;
    }

    /** Kept package-visible for deterministic tests without sending traffic. Despite the name,
     * also recognises the other CDN debug-header disclosures the same probe requests can surface
     * (Akamai's extracted-values/nonces/check-cacheable Pragma directives, Fastly-Debug's routing
     * headers, see {@link #additionalDebugDisclosureFinding}), not only the literal cache key: all
     * of these only ever appear because a client explicitly asked for CDN debug output, so they
     * belong to the exact same "should not be reachable from the public Internet" finding family. */
    public static List<HeaderFinding> cacheKeyDisclosureFindings(Map<String, String> headers) {
        List<HeaderFinding> findings = new ArrayList<>();
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            String name = entry.getKey();
            String value = entry.getValue();
            if (value == null || value.isBlank()) continue;
            boolean standardCacheStatusKey = name.equalsIgnoreCase("Cache-Status")
                    && Pattern.compile("(?i)(?:^|[;,]\\s*)key=(?:\"[^\"]+\"|[^;,\\s]+)")
                        .matcher(value).find();
            if (isCacheKeyResponseHeader(name) || standardCacheStatusKey) {
                String evidence = name + ": " + value.trim();
                findings.add(new HeaderFinding(
                        "HTTP cache key disclosed through debug response",
                        name, value.trim(),
                        "The active cache-debug request caused the response to disclose the cache key " +
                                "or its internal key representation. This can reveal which request components " +
                                "partition cached objects and help an attacker identify unkeyed inputs for cache " +
                                "poisoning research. The disclosure does not by itself prove that poisoning is " +
                                "possible. Disable unauthenticated cache diagnostics and remove cache-key debug " +
                                "headers from public responses.",
                        evidence, Severity.LOW, Confidence.CERTAIN,
                        Category.INFORMATION_DISCLOSURE,
                        "https://www.rfc-editor.org/rfc/rfc9211.html#section-6"));
                continue;
            }
            HeaderFinding extra = additionalDebugDisclosureFinding(name, value);
            if (extra != null) findings.add(extra);
        }
        return findings;
    }

    /** Non-cache-key CDN debug disclosures the same probe requests can trigger. Each of these only
     * shows up because the request carried Fastly-Debug or an Akamai Pragma debug directive (see
     * {@link #CACHE_DEBUG_PRAGMA_TOKENS} and {@link #buildCacheDebugRequest}), an ordinary browser
     * never sees them, so their mere presence already confirms the debug surface is reachable. */
    private static HeaderFinding additionalDebugDisclosureFinding(String name, String value) {
        String v = value.trim();
        String evidence = name + ": " + v;
        if (name.equalsIgnoreCase("X-Akamai-Session-Info")) {
            return new HeaderFinding(
                    "Akamai internal property variable values disclosed via debug header",
                    name, v,
                    "The akamai-x-get-extracted-values / akamai-x-get-nonces Pragma debug directive caused " +
                            "Akamai to echo back the live value of a variable declared inside this property's " +
                            "configuration. Depending on how the property is built, this can include internal " +
                            "origin hostnames, feature flags, or other configuration data never meant to reach " +
                            "a client. Akamai variables default to hidden/sensitive, so a real value appearing " +
                            "here means that protection was explicitly disabled for this variable. Disable " +
                            "Pragma debug headers for unauthenticated traffic, or re-enable the hidden/sensitive " +
                            "options on the variable.",
                    evidence, Severity.MEDIUM, Confidence.CERTAIN,
                    Category.INFORMATION_DISCLOSURE,
                    "https://techdocs.akamai.com/property-mgr/reference/debug-variables");
        }
        if (name.equalsIgnoreCase("X-Check-Cacheable")) {
            return new HeaderFinding(
                    "Akamai cacheability decision disclosed via debug header",
                    name, v,
                    "The akamai-x-check-cacheable Pragma debug directive caused Akamai to disclose whether " +
                            "this exact request is considered cacheable. Minor on its own, but confirms Pragma " +
                            "debug headers are honoured for this property, aiding cache-behaviour reconnaissance " +
                            "ahead of cache poisoning/deception research.",
                    evidence, Severity.LOW, Confidence.CERTAIN,
                    Category.INFORMATION_DISCLOSURE,
                    "https://techdocs.akamai.com/edge-diagnostics/docs/pragma-headers");
        }
        if (name.equalsIgnoreCase("Fastly-Debug-Path") || name.equalsIgnoreCase("Fastly-Debug-Digest")
                || name.equalsIgnoreCase("Fastly-Debug-TTL")) {
            return new HeaderFinding(
                    "Fastly internal cache routing disclosed via debug header",
                    name, v,
                    "The Fastly-Debug request header caused Fastly to disclose internal VCL routing / " +
                            "cache-key digest / TTL decisions (" + name + ") for this request. This exposes " +
                            "internal request-handling and caching logic that should only be reachable from " +
                            "Fastly's own debugging tools, the same research value as an explicit cache-key " +
                            "disclosure.",
                    evidence, Severity.LOW, Confidence.CERTAIN,
                    Category.INFORMATION_DISCLOSURE,
                    "https://www.fastly.com/documentation/reference/http/http-headers/" + name + "/");
        }
        if (name.equalsIgnoreCase("X-Remap")) {
            return new HeaderFinding(
                    "Backend origin URL disclosed via Apache Traffic Server debug header",
                    name, v,
                    "The X-Debug request header caused Apache Traffic Server's xdebug plugin to disclose the " +
                            "remap.config rule (the internal 'from' and 'to' URLs) that routed this request, " +
                            "which can reveal the real origin hostname/path behind the CDN. This is the same " +
                            "direct WAF/CDN-bypass value as X-Backend-Server/X-Origin-Server. Disable the " +
                            "xdebug plugin, or restrict the X-Debug header to trusted internal callers.",
                    evidence, Severity.MEDIUM, Confidence.CERTAIN,
                    Category.INFORMATION_DISCLOSURE,
                    "https://docs.trafficserver.apache.org/en/latest/admin-guide/plugins/xdebug.en.html");
        }
        if (name.equalsIgnoreCase("X-ParentSelection-Key")) {
            return new HeaderFinding(
                    "Internal parent-cache selection key disclosed via Apache Traffic Server debug header",
                    name, v,
                    "The X-Debug request header caused Apache Traffic Server's xdebug plugin to disclose the " +
                            "key used to select a parent cache for this object. Reveals which request components " +
                            "partition selection between tiers, the same cache-poisoning research value as an " +
                            "explicit cache-key disclosure. Disable the xdebug plugin, or restrict the X-Debug " +
                            "header to trusted internal callers.",
                    evidence, Severity.LOW, Confidence.CERTAIN,
                    Category.INFORMATION_DISCLOSURE,
                    "https://docs.trafficserver.apache.org/en/latest/admin-guide/plugins/xdebug.en.html");
        }
        return null;
    }

    private static boolean isCacheKeyResponseHeader(String name) {
        if (name == null) return false;
        String n = name.trim().toLowerCase();
        // Cache-key response names are not standardized across products. Match the semantic
        // family conservatively instead of maintaining a permanently incomplete vendor list;
        // this includes X-True-Cache-Key, X-Akamai-Cache-Key, X-Ghost-Cache-Key-Extra, etc., but
        // deliberately excludes unrelated Surrogate-Key/Edge-Cache-Tag/CF-RAY identifiers.
        return n.matches("(?:x-)?(?:[a-z0-9]+-)*(?:true-)?cache-?key(?:-[a-z0-9-]+)?");
    }

    // ------ HTTP → HTTPS downgrade / HSTS enforcement probe ---------------------------------------------------------------------------

    private UrlAnalysisResult hstsProbe(String url) {
        if (!url.toLowerCase().startsWith("https://")) return null; // only meaningful starting from https
        String httpUrl = "http://" + url.substring("https://".length());

        HttpRequest req = HttpRequest.httpRequestFromUrl(httpUrl);
        HttpRequestResponse rr = sender.send(req);
        if (rr.response() == null) return null;
        // Montoya returns a non-null placeholder Response with statusCode 0 for a probe that
        // never actually connected (refused/timed out/no route on port 80). That is not evidence
        // of a missing redirect, it's evidence the probe itself failed, so treat it the same as
        // a null response rather than let it fall through as "did not redirect (got 0)".
        if (rr.response().statusCode() <= 0) return null;

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

    // ------ WebDAV extension probe ---------------------------------------------------------------------------------------------------------------------

    /** A plain OPTIONS request is enough to fingerprint IIS's WebDAV extension: confirmed against
     * Microsoft's own MS-WDVSE spec and multiple public fingerprinting write-ups, a WebDAV-enabled
     * IIS answers OPTIONS with a "DAV" header (e.g. "DAV: 1,2") and "MS-Author-Via: DAV", and its
     * Allow/Public header lists WebDAV-only verbs (PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK,
     * UNLOCK) alongside the ordinary ones. WebDAV materially widens the attack surface (PUT-based
     * file upload, PROPFIND directory enumeration, historically source-disclosure bugs like the
     * IIS 5.x 'Translate: f' issue), so its mere presence is worth flagging even though this probe
     * does not attempt any of those follow-on techniques itself. */
    private UrlAnalysisResult webDavProbe(String url) {
        HttpRequest req = HttpRequest.httpRequestFromUrl(url).withMethod("OPTIONS");
        HttpRequestResponse rr = sender.send(req);
        if (rr == null || rr.response() == null) return null;

        Map<String, String> headerMap = collectHeaders(rr);
        String dav = headerMap.getOrDefault("DAV", "");
        String msAuthorVia = headerMap.getOrDefault("MS-Author-Via", "");
        boolean webDavConfirmed = !dav.isBlank()
                && msAuthorVia.toLowerCase(java.util.Locale.ROOT).contains("dav");
        if (!webDavConfirmed) return null;

        UrlAnalysisResult result = engine.analyze(url, headerMap, rr.response().statusCode(),
                rr.response().bodyToString(), rr.request().method());
        result = tag(result, rr, LABEL_WEBDAV_PROBE);

        String allow = headerMap.getOrDefault("Allow", headerMap.getOrDefault("Public", ""));
        List<HeaderFinding> extra = new ArrayList<>();
        findingsAdd(extra, "WebDAV extension enabled (IIS)",
                "DAV", "OPTIONS " + url + "  ->  DAV: " + dav + "  |  MS-Author-Via: " + msAuthorVia
                        + (allow.isBlank() ? "" : "  |  Allow/Public: " + allow),
                "The server confirmed IIS's WebDAV extension is enabled by answering OPTIONS with a DAV " +
                        "header and MS-Author-Via: DAV. WebDAV meaningfully widens the attack surface: " +
                        "PROPFIND-based directory/content enumeration, PUT-based file upload if write access " +
                        "is misconfigured, and (on older/legacy IIS builds) source-disclosure techniques such " +
                        "as the 'Translate: f' header. Disable the WebDAV Publishing feature if it is not " +
                        "actually required.",
                Severity.MEDIUM, Confidence.CERTAIN,
                "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wdvse/626ff89b-8938-4c31-b868-d9b3824a92f4");
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
