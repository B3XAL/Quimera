package com.b3xal.headeranalyzer.analyzer;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.b3xal.headeranalyzer.config.CookiesAndAuthConfig;
import com.b3xal.headeranalyzer.config.QuimeraSettings;
import com.b3xal.headeranalyzer.model.HeaderFinding;
import com.b3xal.headeranalyzer.model.Severity;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.*;

class CookieInfluenceProbeTest {
    private static final String URL = "https://example.test/page?id=1";
    private static final CookiesAndAuthConfig CONFIG = new QuimeraSettings().cookiesAndAuthConfig();

    // ---------- Classification: false positives (never mutate sensitive cookies) ----------------

    @Test
    void neverMutatesSessionAuthOrCsrfCookies() {
        for (String name : List.of("JSESSIONID", "sessionid", "PHPSESSID", "SID", "auth", "auth_token",
                "access_token", "id_token", "jwt", "sso", "csrf_token", "XSRF-TOKEN",
                "__RequestVerificationToken", "antiforgery")) {
            assertFalse(CookieInfluenceProbe.safeToMutate(name, "shortvalue", CONFIG),
                    "must never mutate sensitive cookie: " + name);
        }
    }

    @Test
    void neverMutatesInfrastructurePrefixedOrSecretNamedCookies() {
        for (String name : List.of("cato_fw_inet", "fw_wan", "__Host-session", "__Secure-token",
                "client_secret", "password", "api_key", "api-key", "apikey", "signature", "nonce")) {
            assertFalse(CookieInfluenceProbe.safeToMutate(name, "value", CONFIG),
                    "must never mutate protected cookie: " + name);
        }
    }

    @Test
    void neverMutatesCredentialShapedValuesEvenUnderBenignNames() {
        // A benign name must not be a blind spot: a JWT or opaque/high-entropy token value is
        // treated as credential material and left untouched.
        assertFalse(CookieInfluenceProbe.safeToMutate("prefs",
                "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.sig", CONFIG), "JWT-shaped value");
        assertFalse(CookieInfluenceProbe.safeToMutate("ui",
                "9c8b7a6f5e4d3c2b1a0987654321fedcba098765", CONFIG), "opaque high-entropy value");
        assertFalse(CookieInfluenceProbe.safeToMutate("state",
                "a".repeat(300), CONFIG), "oversized value");
        assertFalse(CookieInfluenceProbe.safeToMutate("empty", "", CONFIG), "empty value");
    }

    // ---------- Classification: silent failures (do not over-exclude real candidates) -----------

    @Test
    void doesMutateOrdinaryPreferenceCookies() {
        for (String[] nv : new String[][]{{"lang", "en-US"}, {"theme", "dark"}, {"currency", "EUR"},
                {"view", "grid"}, {"tab", "overview"}, {"sort", "price"}}) {
            assertTrue(CookieInfluenceProbe.safeToMutate(nv[0], nv[1], CONFIG),
                    "preference cookie should be mutable: " + nv[0] + "=" + nv[1]);
        }
    }

    @Test
    void candidatesKeepsOnlySafeCookiesDedupedAndCapped() {
        Map<String, String> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        headers.put("Cookie", "JSESSIONID=abc; lang=en-US; csrf_token=zzz; theme=dark; lang=dup; currency=EUR");
        List<CookieInfluenceProbe.CookieCandidate> candidates =
                CookieInfluenceProbe.candidates(cookieRequest(URL, "GET", headers), CONFIG);
        List<String> names = candidates.stream().map(CookieInfluenceProbe.CookieCandidate::name).toList();
        assertEquals(List.of("lang", "theme", "currency"), names,
                "only non-sensitive cookies, first value per name, session/csrf excluded");
    }

    // ---------- End-to-end: real detection, no silent failure -----------------------------------

    @Test
    void reflectedPreferenceCookieIsReportedAsInfoAndSessionCookieStaysIntact() {
        var rig = new Rig(req -> response(req, 200, Map.of("Content-Type", "text/html"),
                "<p>" + Objects.toString(cookie(req, "lang"), "none") + "</p>"));
        HttpRequest template = cookieRequest(URL, "GET",
                headerMap("Cookie", "JSESSIONID=SECRET-SESSION; lang=en-US"));
        var results = rig.probe.probe(rig.exchange(template));
        var finding = results.stream().flatMap(r -> r.findings.stream())
                .filter(f -> f.issueName.equals("Request cookie value reflected: lang")).findFirst().orElseThrow();
        assertEquals(Severity.INFORMATION, finding.severity);
        assertTrue(finding.description.contains("not XSS"), "must carry the no-XSS/delivery caveat");
        // Session safety invariant: JSESSIONID is sent unchanged on EVERY probe request.
        assertTrue(rig.requests.stream().allMatch(r -> "SECRET-SESSION".equals(cookie(r, "JSESSIONID"))),
                "session cookie must never be altered by the probe");
    }

    @Test
    void cookieThatControlsResponseWithoutReflectionIsInfoInfluence() {
        var rig = new Rig(req -> response(req, 200, Map.of("Content-Type", "text/plain"),
                "en-US".equals(cookie(req, "lang")) ? "English content" : "Translated content"));
        HttpRequest template = cookieRequest(URL, "GET", headerMap("Cookie", "lang=en-US"));
        var findings = rig.probe.probe(rig.exchange(template)).stream().flatMap(r -> r.findings.stream()).toList();
        assertTrue(findings.stream().anyMatch(f -> f.issueName.equals("Request cookie controls response: lang")
                && f.severity == Severity.INFORMATION));
        assertTrue(findings.stream().noneMatch(f -> f.issueName.contains("XSS")));
    }

    // ---------- End-to-end: false-positive guards -----------------------------------------------

    @Test
    void routineDynamicIdWithoutReflectionProducesNoFinding() {
        AtomicInteger n = new AtomicInteger();
        var rig = new Rig(req -> response(req, 200,
                Map.of("Content-Type", "text/plain", "X-Request-Id", "id-" + n.incrementAndGet()), "stable body"));
        assertTrue(rig.probe.probe(rig.exchange(cookieRequest(URL, "GET", headerMap("Cookie", "lang=en-US")))).isEmpty());
    }

    @Test
    void markerLeakingIntoCleanControlsIsNotReportedAsReflection() {
        // Simulated cache/persistence: once seen, the value sticks even in clean controls.
        String[] stuck = {"en-US"};
        var rig = new Rig(req -> {
            String value = cookie(req, "lang");
            if (value != null && !value.equals("en-US")) stuck[0] = value;
            return response(req, 200, Map.of("Content-Type", "text/html"), "<p>" + stuck[0] + "</p>");
        });
        assertTrue(rig.probe.probe(rig.exchange(cookieRequest(URL, "GET", headerMap("Cookie", "lang=en-US")))).isEmpty());
    }

    @Test
    void errorPageResponsesCannotConfirmAnything() {
        var rig = new Rig(req -> response(req, 200, Map.of("Content-Type", "text/html"),
                "<title>Just a moment</title>" + Objects.toString(cookie(req, "lang"), "")));
        assertTrue(rig.probe.probe(rig.exchange(cookieRequest(URL, "GET", headerMap("Cookie", "lang=en-US")))).isEmpty());
    }

    @Test
    void noMutableCookiesMeansNoRequestsAtAll() {
        // Only session/auth cookies: the probe must send nothing, never a mutated session request.
        var rig = new Rig(req -> response(req, 200, Map.of(), "clean"));
        rig.probe.probe(rig.exchange(cookieRequest(URL, "GET",
                headerMap("Cookie", "JSESSIONID=abc; csrf_token=def"))));
        assertEquals(0, rig.requests.size(), "no safe cookie -> no probe traffic");
    }

    @Test
    void disabledProbeSendsNothing() {
        var rig = new Rig(req -> response(req, 200, Map.of(), "clean"));
        rig.settings.setCookieInfluenceProbeEnabled(false);
        rig.probe.probe(rig.exchange(cookieRequest(URL, "GET", headerMap("Cookie", "lang=en-US"))));
        assertEquals(0, rig.requests.size());
    }

    // ---------- harness ------------------------------------------------------------------------

    private static final class Rig {
        final QuimeraSettings settings = new QuimeraSettings();
        final AtomicLong now = new AtomicLong();
        final List<HttpRequest> requests = new ArrayList<>();
        final Function<HttpRequest, HttpRequestResponse> responder;
        final CookieInfluenceProbe probe;
        Rig(Function<HttpRequest, HttpRequestResponse> responder) {
            this.responder = responder;
            settings.setCookieInfluenceProbeEnabled(true);
            probe = new CookieInfluenceProbe(null, settings, req -> {
                requests.add(req); return responder.apply(req);
            }, now::get, now::addAndGet);
        }
        HttpRequestResponse exchange(HttpRequest req) { return responder.apply(req); }
    }

    private interface Call { Object apply(Object[] args); }

    @SuppressWarnings("unchecked")
    private static <T> T fake(Class<T> type, Map<String, Call> methods) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, (p, m, args) -> {
            if (methods.containsKey(m.getName())) return methods.get(m.getName()).apply(args);
            if (m.getName().equals("equals")) return p == args[0];
            if (m.getName().equals("hashCode")) return System.identityHashCode(p);
            if (m.getReturnType() == boolean.class) return false;
            if (m.getReturnType() == int.class) return 0;
            return null;
        });
    }

    private static Map<String, String> headerMap(String... kv) {
        Map<String, String> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        for (int i = 0; i < kv.length; i += 2) headers.put(kv[i], kv[i + 1]);
        return headers;
    }

    private static LinkedHashMap<String, String> parseCookieHeader(String cookieHeader) {
        LinkedHashMap<String, String> cookies = new LinkedHashMap<>();
        if (cookieHeader == null) return cookies;
        for (String part : cookieHeader.split(";")) {
            String p = part.trim();
            if (p.isEmpty()) continue;
            int eq = p.indexOf('=');
            if (eq < 0) continue;
            cookies.putIfAbsent(p.substring(0, eq).trim(), p.substring(eq + 1).trim());
        }
        return cookies;
    }

    private static String renderCookieHeader(LinkedHashMap<String, String> cookies) {
        return cookies.entrySet().stream().map(e -> e.getKey() + "=" + e.getValue())
                .reduce((a, b) -> a + "; " + b).orElse("");
    }

    /** Reads one cookie's value from a request's Cookie header (test responder convenience). */
    private static String cookie(HttpRequest req, String name) {
        return parseCookieHeader(req.headerValue("Cookie")).get(name);
    }

    static HttpRequest cookieRequest(String url, String method, Map<String, String> input) {
        Map<String, String> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        headers.putAll(input);
        return fake(HttpRequest.class, Map.ofEntries(
                Map.entry("url", a -> url),
                Map.entry("method", a -> method),
                Map.entry("headers", a -> headerList(headers)),
                Map.entry("headerValue", a -> headers.get((String) a[0])),
                Map.entry("hasHeader", a -> headers.containsKey((String) a[0])),
                Map.entry("header", a -> headers.containsKey((String) a[0])
                        ? header((String) a[0], headers.get((String) a[0])) : null),
                Map.entry("withHeader", a -> {
                    var copy = new TreeMap<>(headers); copy.put((String) a[0], (String) a[1]);
                    return cookieRequest(url, method, copy);
                }),
                Map.entry("parameters", a -> cookieParams(headers.get("Cookie"))),
                Map.entry("withUpdatedParameters", a -> {
                    LinkedHashMap<String, String> cookies = parseCookieHeader(headers.get("Cookie"));
                    for (HttpParameter param : (HttpParameter[]) a[0])
                        if (param.type() == HttpParameterType.COOKIE) cookies.put(param.name(), param.value());
                    var copy = new TreeMap<>(headers); copy.put("Cookie", renderCookieHeader(cookies));
                    return cookieRequest(url, method, copy);
                }),
                Map.entry("toString", a -> method + " " + url + "\r\n" + headers)));
    }

    private static List<ParsedHttpParameter> cookieParams(String cookieHeader) {
        List<ParsedHttpParameter> out = new ArrayList<>();
        parseCookieHeader(cookieHeader).forEach((name, value) -> out.add(fake(ParsedHttpParameter.class, Map.of(
                "type", a -> HttpParameterType.COOKIE, "name", a -> name, "value", a -> value))));
        return out;
    }

    private static HttpHeader header(String name, String value) {
        return fake(HttpHeader.class, Map.of("name", a -> name, "value", a -> value,
                "toString", a -> name + ": " + value));
    }
    private static List<HttpHeader> headerList(Map<String, String> headers) {
        return headers.entrySet().stream().map(e -> header(e.getKey(), e.getValue())).toList();
    }
    private static HttpRequestResponse response(HttpRequest req, int status, Map<String, String> input, String body) {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        Map<String, String> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER); headers.putAll(input);
        ByteArray ba = fake(ByteArray.class, Map.of("length", a -> bytes.length, "getBytes", a -> bytes));
        HttpResponse response = fake(HttpResponse.class, Map.of("statusCode", a -> (short) status,
                "headers", a -> headerList(headers), "headerValue", a -> headers.get((String) a[0]),
                "body", a -> ba, "bodyToString", a -> body,
                "toString", a -> "HTTP/1.1 " + status + "\r\n" + headers + "\r\n\r\n" + body));
        return fake(HttpRequestResponse.class, Map.of("request", a -> req, "response", a -> response));
    }
}
