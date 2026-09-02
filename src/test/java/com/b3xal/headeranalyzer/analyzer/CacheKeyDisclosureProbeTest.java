package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.model.Confidence;
import com.b3xal.headeranalyzer.model.HeaderFinding;
import com.b3xal.headeranalyzer.model.Severity;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CacheKeyDisclosureProbeTest {
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
    void ignoresCacheStatusIdsTagsAndEmptyKeys() {
        assertTrue(ActiveHeaderScanner.cacheKeyDisclosureFindings(Map.of(
                "CF-RAY", "abc-MAD", "X-Cache", "HIT", "X-Served-By", "cache-1",
                "Surrogate-Key", "article-1", "X-Cache-Key", "")).isEmpty());
    }
}
