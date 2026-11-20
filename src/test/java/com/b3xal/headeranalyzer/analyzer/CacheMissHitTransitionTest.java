package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.model.Confidence;
import com.b3xal.headeranalyzer.model.HeaderFinding;
import com.b3xal.headeranalyzer.model.Severity;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CacheMissHitTransitionTest {
    @Test
    void confirmsCloudflareMissToHit() {
        var finding = ActiveHeaderScanner.cacheTransitionFinding(
                Map.of("CF-Cache-Status", "MISS"),
                Map.of("CF-Cache-Status", "HIT", "Age", "2"));
        assertEquals(Severity.INFORMATION, finding.severity);
        assertEquals(Confidence.CERTAIN, finding.confidence);
        assertEquals(HeaderFinding.Category.INFORMATION_DISCLOSURE, finding.category);
        assertTrue(finding.evidence.contains("MISS"));
        assertTrue(finding.evidence.contains("HIT"));
    }

    @Test
    void confirmsRfcCacheStatusAndAkamaiFormats() {
        assertTrue(ActiveHeaderScanner.cacheTransitionFinding(
                Map.of("Cache-Status", "CDN; fwd=uri-miss"),
                Map.of("Cache-Status", "CDN; hit; ttl=60")) != null);
        assertTrue(ActiveHeaderScanner.cacheTransitionFinding(
                Map.of("X-Cache", "TCP_MISS from edge"),
                Map.of("X-Cache", "TCP_HIT from edge")) != null);
    }

    @Test
    void rejectsMissToMissAndHitsOlderThanOneHour() {
        assertNull(ActiveHeaderScanner.cacheTransitionFinding(
                Map.of("X-Cache", "MISS"), Map.of("X-Cache", "MISS")));
        assertNull(ActiveHeaderScanner.cacheTransitionFinding(
                Map.of("X-Cache", "MISS"),
                Map.of("X-Cache", "HIT", "Age", "3601")));
    }
}
