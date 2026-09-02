package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.config.QuimeraSettings;
import com.b3xal.headeranalyzer.model.DomainData;
import com.b3xal.headeranalyzer.model.HeaderFinding;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SharedCacheEvidenceTest {
    private final HeaderAnalysisEngine engine =
            new HeaderAnalysisEngine(new RuleStore(null), new QuimeraSettings());

    @Test
    void reportsExplicitHitAndUsefulAgeAsOneInformationalFinding() {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Content-Type", "text/html");
        headers.put("X-Cache", "HIT from cloudfront");
        headers.put("Age", "37");

        var cache = engine.analyze("https://example.test/", headers, 200, "GET").findings.stream()
                .filter(f -> f.issueName.equals("Shared HTTP cache activity detected")).toList();
        assertEquals(1, cache.size());
        assertEquals(com.b3xal.headeranalyzer.model.Confidence.CERTAIN, cache.get(0).confidence);
        assertTrue(cache.get(0).evidence.contains("X-Cache: HIT"));
        assertTrue(cache.get(0).evidence.contains("Age: 37"));
    }

    @Test
    void acceptsStandardCacheStatusHitAndPositiveHitCounter() {
        var first = engine.analyze("https://example.test/a",
                Map.of("Cache-Status", "ExampleCache; hit; ttl=120"), 200, "GET");
        var second = engine.analyze("https://example.test/b",
                Map.of("X-Cache-Hits", "0, 2"), 200, "GET");
        assertTrue(hasCacheFinding(first));
        assertTrue(hasCacheFinding(second));
    }

    @Test
    void acceptsCommonVendorAndServerTimingHitFormats() {
        for (Map<String, String> headers : List.of(
                Map.of("X-Cache", "Hit from cloudfront"),
                Map.of("X-Cache", "TCP_HIT from a23-45-67-89.deploy.akamaitechnologies.com"),
                Map.of("X-Cache", "TCP_MEM_HIT"),
                Map.of("X-Cache", "hit-fresh"),
                Map.of("X-Cache-Status", "HIT"),
                Map.of("X-Cache-Status", "STALE"),
                Map.of("X-Cache-Status", "UPDATING"),
                Map.of("X-Cache-Status", "REVALIDATED"),
                Map.of("X-FastCGI-Cache", "HIT"),
                Map.of("X-LiteSpeed-Cache", "hit"),
                Map.of("X-Kinsta-Cache", "HIT"),
                Map.of("Server-Timing", "cfCacheStatus;desc=\"HIT\""),
                Map.of("Server-Timing", "cdn-cache-hit,cdn-pop;desc=\"MAD50-C1\""),
                Map.of("Server-Timing", "cdn-cache-refresh;desc=\"Hit from cloudfront\""))) {
            assertTrue(hasCacheFinding(engine.analyze(
                    "https://example.test/", headers, 200, "GET")), headers.toString());
        }
    }

    @Test
    void ignoresMissZeroInvalidAndAgeOverOneHour() {
        for (Map<String, String> headers : List.of(
                Map.of("X-Cache", "MISS"), Map.of("Age", "0"), Map.of("Age", "invalid"),
                Map.of("Age", "3601"), Map.of("Age", "172800"), Map.of("Age", "2147483648"),
                Map.of("X-Cache-Hits", "0"),
                Map.of("Cache-Status", "ExampleCache; fwd=stale; stored"),
                Map.of("Server-Timing", "cdn-cache-miss"),
                Map.of("X-Cache-Status", "EXPIRED"),
                Map.of("CF-Cache-Status", "BYPASS"))) {
            assertFalse(hasCacheFinding(engine.analyze(
                    "https://example.test/", headers, 200, "GET")));
        }
    }

    @Test
    void acceptsAgeAtOneHourBoundary() {
        assertTrue(hasCacheFinding(engine.analyze("https://example.test/",
                Map.of("Age", "3600"), 200, "GET")));
    }

    @Test
    void ignoresExplicitHitWhenAgeIsOverOneHour() {
        assertFalse(hasCacheFinding(engine.analyze("https://example.test/",
                Map.of("CF-Cache-Status", "HIT", "Age", "3601"), 200, "GET")));
    }

    @Test
    void acceptsExplicitHitWhenAgeIsAbsent() {
        assertTrue(hasCacheFinding(engine.analyze("https://example.test/",
                Map.of("CF-Cache-Status", "HIT"), 200, "GET")));
    }

    @Test
    void cacheAdvisoryIsRetainedForTheReportDisclosureSection() {
        var result = engine.analyze("https://example.test/cached",
                Map.of("X-Cache", "HIT", "Age", "60"), 200, "GET");
        var finding = result.findings.stream()
                .filter(f -> f.issueName.equals("Shared HTTP cache activity detected"))
                .findFirst().orElseThrow();

        assertEquals(HeaderFinding.Category.INFORMATION_DISCLOSURE, finding.category);
        DomainData domain = new DomainData("example.test");
        domain.addResult(result);
        assertTrue(domain.getDisclosureInventory().stream().anyMatch(f ->
                f.issueName.equals("Shared HTTP cache activity detected")));
    }

    private static boolean hasCacheFinding(com.b3xal.headeranalyzer.model.UrlAnalysisResult result) {
        return result.findings.stream().anyMatch(f ->
                f.issueName.equals("Shared HTTP cache activity detected"));
    }
}
