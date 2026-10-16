package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.config.QuimeraSettings;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NewDisclosureHeaderRulesTest {
    private final HeaderAnalysisEngine engine =
            new HeaderAnalysisEngine(new RuleStore(null), new QuimeraSettings());

    private long countFor(Map<String, String> headers, String headerName) {
        var result = engine.analyze("https://example.test/x", headers, Map.of(), 200, "<html></html>", "GET");
        return result.findings.stream().filter(f -> f.headerName.equalsIgnoreCase(headerName)).count();
    }

    @Test
    void sourceMapAndLegacyXSourceMapBothFire() {
        assertEquals(1, countFor(Map.of("SourceMap", "/static/app.js.map"), "SourceMap"));
        assertEquals(1, countFor(Map.of("X-SourceMap", "/static/app.js.map"), "X-SourceMap"));
    }

    @Test
    void magentoCacheDebugFires() {
        assertEquals(1, countFor(Map.of("X-Magento-Cache-Debug", "HIT"), "X-Magento-Cache-Debug"));
    }

    @Test
    void kongLatencyHeadersFire() {
        assertEquals(1, countFor(Map.of("X-Kong-Proxy-Latency", "1"), "X-Kong-Proxy-Latency"));
        assertEquals(1, countFor(Map.of("X-Kong-Upstream-Latency", "12"), "X-Kong-Upstream-Latency"));
        assertEquals(1, countFor(Map.of("X-Kong-Response-Latency", "3"), "X-Kong-Response-Latency"));
    }

    @Test
    void CloudFrontCacheAndRoutingHeadersDoNotProduceFindings() {
        for (String cacheStatus : new String[]{"Hit from cloudfront", "Miss from cloudfront", "Error from cloudfront"}) {
            var result = engine.analyze("https://example.test/x", Map.of(
                    "X-Cache", cacheStatus,
                    "Via", "1.1 0123456789abcdef0123456789abcdef.cloudfront.net (CloudFront)"),
                    Map.of(), 502, "<html></html>", "GET");

            assertEquals(0, result.findings.stream()
                    .filter(f -> f.headerName.equalsIgnoreCase("X-Cache")
                            || f.headerName.equalsIgnoreCase("Via"))
                    .count(), cacheStatus);
        }
    }

    @Test
    void genericCacheStatusHeadersDoNotCreateStandaloneFindings() {
        var result = engine.analyze("https://example.test/x",
                Map.of("X-Cache", "HIT", "X-Cache-Hits", "2", "X-Cache-Hit", "true"),
                Map.of(), 200, "<html></html>", "GET");
        var findings = result.findings.stream()
                .filter(f -> f.headerName.equalsIgnoreCase("X-Cache")
                        || f.headerName.equalsIgnoreCase("X-Cache-Hits")
                        || f.headerName.equalsIgnoreCase("X-Cache-Hit")).toList();
        assertEquals(0, findings.size());
    }

    @Test
    void serverTimingDoesNotProduceNoiseButStillFlagsCredentialLabelledValues() {
        var ordinary = engine.analyze("https://example.test/x", Map.of(
                "Server-Timing", "db;dur=14.2, cdn-cache-hit;desc=HIT, edge;desc=mad"),
                Map.of(), 200, "<html></html>", "GET");
        assertEquals(0, ordinary.findings.stream()
                .filter(f -> f.headerName.equalsIgnoreCase("Server-Timing")).count());

        var sensitive = engine.analyze("https://example.test/x", Map.of(
                "Server-Timing", "auth;desc=access_token=Abcdefghijklmnop"),
                Map.of(), 200, "<html></html>", "GET");
        assertEquals(1, sensitive.findings.stream()
                .filter(f -> f.headerName.equalsIgnoreCase("Server-Timing")
                        && f.issueName.equals("Potential credential in Server-Timing metadata")).count());
    }

    @Test
    void technologyOnlyHeadersStayInTechnologyInventoryWithoutCreatingFindings() {
        var result = engine.analyze("https://example.test/x", Map.of(
                "X-Varnish", "12345",
                "X-Envoy-Upstream-Service-Time", "17",
                "X-Pingback", "https://example.test/xmlrpc.php",
                "X-Cache", "HIT",
                "X-Cache-Hits", "2",
                "X-Cache-Hit", "true",
                "Timing-Allow-Origin", "*"), Map.of(), 200, "<html></html>", "GET");

        assertEquals(0, result.findings.stream().filter(f ->
                f.headerName.equalsIgnoreCase("X-Varnish")
                        || f.headerName.equalsIgnoreCase("X-Envoy-Upstream-Service-Time")
                        || f.headerName.equalsIgnoreCase("X-Pingback")
                        || f.headerName.equalsIgnoreCase("X-Cache")
                        || f.headerName.equalsIgnoreCase("X-Cache-Hits")
                        || f.headerName.equalsIgnoreCase("X-Cache-Hit")
                        || f.headerName.equalsIgnoreCase("Timing-Allow-Origin")).count());
        assertTrue(result.techFindings.stream().anyMatch(t -> t.product.equals("Varnish")));
        assertTrue(result.techFindings.stream().anyMatch(t -> t.product.equals("Envoy")));
        assertTrue(result.techFindings.stream().anyMatch(t -> t.product.equals("WordPress")));
    }

    @Test
    void deprecatedResponseHeadersHaveARelevantAdvisoryLink() {
        var result = engine.analyze("https://example.test/x", Map.of(
                "Warning", "299 example.test \"legacy warning\"",
                "Report-To", "{\"group\":\"default\",\"max_age\":86400}",
                "Content-DPR", "2",
                "Pragma", "no-cache"), Map.of(), 200, "<html></html>", "GET");
        for (String header : new String[]{"Warning", "Report-To", "Content-DPR", "Pragma"}) {
            var findings = result.findings.stream().filter(f -> f.headerName.equalsIgnoreCase(header)).toList();
            assertEquals(1, findings.size(), header);
            assertTrue(findings.get(0).referenceUrl != null && !findings.get(0).referenceUrl.isBlank(), header);
        }
    }
}
