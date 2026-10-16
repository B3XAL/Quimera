package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.config.QuimeraSettings;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SharedCacheEvidenceTest {
    private final HeaderAnalysisEngine engine =
            new HeaderAnalysisEngine(new RuleStore(null), new QuimeraSettings());

    @Test
    void cacheTelemetryNeverCreatesStandaloneFindings() {
        for (Map<String, String> headers : List.of(
                Map.of("X-Cache", "Hit from cloudfront"),
                Map.of("X-Cache", "TCP_HIT from cache.example"),
                Map.of("CF-Cache-Status", "HIT"),
                Map.of("Cache-Status", "ExampleCache; hit; ttl=120"),
                Map.of("X-Cache-Hits", "2"),
                Map.of("Age", "37"),
                Map.of("Server-Timing", "cdn-cache-hit"))) {
            var result = engine.analyze("https://example.test/", headers, 200, "GET");
            assertFalse(result.findings.stream().anyMatch(f ->
                    f.issueName.equals("Shared HTTP cache activity detected")), headers.toString());
        }
    }

    @Test
    void cacheSignalsRemainAvailableOnlyForBoundedInternalProbing() {
        assertTrue(ActiveHeaderScanner.hasCacheEvidence(Map.of("X-Cache", "Hit from cloudfront")));
        assertTrue(ActiveHeaderScanner.hasCacheEvidence(Map.of("Cache-Status", "edge; hit")));
        // A MISS still proves that a shared cache is in the request path. It is
        // useful only as an internal eligibility signal for bounded active
        // cache probes; it must never become a standalone passive finding.
        assertTrue(ActiveHeaderScanner.hasCacheEvidence(Map.of("X-Cache", "MISS")));
    }
}
