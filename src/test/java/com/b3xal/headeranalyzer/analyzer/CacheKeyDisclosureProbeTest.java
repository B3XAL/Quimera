package com.b3xal.headeranalyzer.analyzer;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.HttpHeader;
import com.b3xal.headeranalyzer.config.QuimeraSettings;
import com.b3xal.headeranalyzer.model.Confidence;
import com.b3xal.headeranalyzer.model.HeaderFinding;
import com.b3xal.headeranalyzer.model.Severity;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.LinkedHashMap;
import java.lang.reflect.Proxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CacheKeyDisclosureProbeTest {
    private final HeaderAnalysisEngine engine =
            new HeaderAnalysisEngine(new RuleStore(null), new QuimeraSettings());

    @Test
    void cacheDebugAttemptReplacesBrowserNoCachePragmaSoTokenIsActuallyIsolated() {
        HttpRequest captured = requestWithHeaders(Map.of(
                "Cookie", "session=keep-me", "Pragma", "no-cache",
                "Connection", "Upgrade", "Upgrade", "websocket"));

        HttpRequest probe = ActiveHeaderScanner.buildCacheDebugRequest(
                "https://example.test/post?postId=4", captured, "x-get-cache-key");

        assertEquals("x-get-cache-key", probe.header("Pragma").value());
        assertEquals("session=keep-me", probe.header("Cookie").value());
        assertEquals(null, probe.header("Upgrade"));
        assertEquals(null, probe.header("Connection"));
        assertEquals("no-cache", captured.header("Pragma").value());
    }

    /** Root cause of a real, extended, multi-session bug: ordinary subresource fetches (images,
     * CSS, JS, and most fetch()-driven endpoints like academyLabHeader) never carry a Pragma header
     * at all, only some top-level navigations happen to. withUpdatedHeader only promises to update
     * an EXISTING header, so relying on it here meant the probe silently sent no diagnostic Pragma
     * for the majority of real traffic, always getting a plain response back with no evidence
     * either way, indistinguishable from "this app just doesn't echo the key". */
    @Test
    void cacheDebugAttemptAddsPragmaAndDebugHeadersEvenWhenTemplateHasNoneAtAll() {
        HttpRequest captured = requestWithHeaders(Map.of("Accept", "*/*", "Origin", "https://example.test"));

        HttpRequest probe = ActiveHeaderScanner.buildCacheDebugRequest(
                "https://example.test/academyLabHeader", captured, "x-get-cache-key");

        assertEquals("x-get-cache-key", probe.header("Pragma").value());
        assertEquals("cache", probe.header("Akamai-Debug").value());
        assertEquals("1", probe.header("Fastly-Debug").value());
        assertEquals("1", probe.header("X-Cache-Debug").value());
    }

    private static HttpRequest requestWithHeaders(Map<String, String> input) {
        Map<String, String> headers = new LinkedHashMap<>(input);
        return (HttpRequest) Proxy.newProxyInstance(HttpRequest.class.getClassLoader(),
                new Class<?>[]{HttpRequest.class}, (proxy, method, args) -> {
                    if (method.getName().equals("header")) {
                        String value = headers.get((String) args[0]);
                        if (value == null) return null;
                        String name = (String) args[0];
                        return Proxy.newProxyInstance(HttpHeader.class.getClassLoader(),
                                new Class<?>[]{HttpHeader.class}, (p, m, a) -> switch (m.getName()) {
                                    case "name" -> name;
                                    case "value" -> value;
                                    case "toString" -> name + ": " + value;
                                    default -> null;
                                });
                    }
                    if (method.getName().equals("withUpdatedHeader")) {
                        // Faithful to Montoya's own javadoc: "update the value of an existing
                        // header" promises nothing about adding one that isn't there, unlike
                        // withHeader's documented "add or update". A looser mock here already
                        // masked a real bug (buildCacheDebugRequest silently sent no Pragma at all
                        // for any template that didn't already have one) for a long time.
                        if (!headers.containsKey((String) args[0])) return proxy;
                        Map<String, String> updated = new LinkedHashMap<>(headers);
                        updated.put((String) args[0], (String) args[1]);
                        return requestWithHeaders(updated);
                    }
                    if (method.getName().equals("withHeader")) {
                        Map<String, String> updated = new LinkedHashMap<>(headers);
                        updated.put((String) args[0], (String) args[1]);
                        return requestWithHeaders(updated);
                    }
                    if (method.getName().equals("withRemovedHeader")) {
                        Map<String, String> updated = new LinkedHashMap<>(headers);
                        updated.remove((String) args[0]);
                        return requestWithHeaders(updated);
                    }
                    if (method.getName().equals("withMethod")
                            || method.getName().equals("withBody")) return proxy;
                    if (method.getName().equals("method")) return "GET";
                    if (method.getName().equals("toString")) return headers.toString();
                    if (method.getReturnType() == boolean.class) return false;
                    if (method.getReturnType() == int.class) return 0;
                    return null;
                });
    }

    /** A backend/CDN can echo its cache key on ordinarily observed traffic (e.g. because the
     * client itself already sent a debug pragma), with no active probe involved at all. This must
     * be reported the moment Quimera sees that response, not only when its own active cache-key
     * probe happens to reproduce the same disclosure on a fresh replay. */
    @Test
    void reportsCacheKeyDisclosurePassivelyWithoutAnyActiveProbe() {
        var result = engine.analyze("https://example.test/post?postId=4",
                Map.of("Content-Type", "text/html", "X-Cache-Key", "/$$", "X-Cache", "hit"),
                Map.of("Pragma", "x-get-cache-key"), 200, "<html></html>", "GET");
        var findings = result.findings.stream()
                .filter(f -> f.issueName.equals("HTTP cache key disclosed through debug response"))
                .toList();
        assertEquals(1, findings.size());
        assertEquals("X-Cache-Key", findings.get(0).headerName);
    }

    @Test
    void detectsAkamaiAndCommonCacheKeyResponseVariants() {
        for (String name : new String[]{"X-Cache-Key", "X-True-Cache-Key",
                "X-Cache-Key-Extended-Internal-Use-Only", "X-Akamai-Cache-Key",
                "X-Varnish-Cache-Key", "X-Fastly-Cache-Key", "X-Proxy-Cache-Key",
                "X-Nginx-Cache-Key", "X-Ghost-Cache-Key-Extra", "X-CacheKey", "Cache-Key"}) {
            var findings = ActiveHeaderScanner.cacheKeyDisclosureFindings(
                    Map.of(name, "/L/1234/5678/example.test/private"));
            assertEquals(1, findings.size(), name);
            assertEquals(Severity.LOW, findings.get(0).severity);
            assertEquals(Confidence.CERTAIN, findings.get(0).confidence);
            assertEquals(HeaderFinding.Category.INFORMATION_DISCLOSURE,
                    findings.get(0).category);
        }
    }

    @Test
    void detectsStandardRfc9211CacheStatusKeyParameter() {
        var findings = ActiveHeaderScanner.cacheKeyDisclosureFindings(Map.of(
                "Cache-Status", "ExampleCDN; hit; ttl=120; key=\"https://example.test/a\""));
        assertEquals(1, findings.size());
        assertEquals("Cache-Status", findings.get(0).headerName);
    }

    @Test
    void recognisesExplicitAndGenericCacheEvidence() {
        assertTrue(ActiveHeaderScanner.hasExplicitCacheSignal(Map.of("X-Cache", "miss", "Age", "0")));
        assertTrue(ActiveHeaderScanner.hasExplicitCacheSignal(Map.of("Cache-Status", "CDN; hit")));
        assertEquals(false, ActiveHeaderScanner.hasExplicitCacheSignal(
                Map.of("Cache-Control", "max-age=35", "Age", "0")));
        assertTrue(ActiveHeaderScanner.hasCacheEvidence(
                Map.of("Cache-Control", "max-age=35", "Age", "0")));
    }

    @Test
    void ignoresCacheStatusIdsTagsAndEmptyKeys() {
        assertTrue(ActiveHeaderScanner.cacheKeyDisclosureFindings(Map.of(
                "CF-RAY", "abc-MAD", "X-Cache", "HIT", "X-Served-By", "cache-1",
                "Surrogate-Key", "article-1", "X-Cache-Key", "")).isEmpty());
    }
}
