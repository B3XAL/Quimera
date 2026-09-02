package com.b3xal.headeranalyzer.ui;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class DetailPanelEvidenceSearchTest {
    private static final String RESPONSE = """
            HTTP/1.1 200 OK\r
            Server-Timing: cfCacheStatus;desc=\"HIT\"\r
            Age: 507\r
            cf-cache-status: HIT\r
            \r
            """;

    @Test
    void resolvesSyntheticCacheLocationToLiteralResponseHeader() {
        assertEquals("cf-cache-status: HIT", DetailPanel.evidenceFragmentInResponse(
                RESPONSE, "Age: 507 | cf-cache-status: HIT"));
    }

    @Test
    void doesNotReturnSyntheticOrAbsentEvidence() {
        assertNull(DetailPanel.evidenceFragmentInResponse(RESPONSE, "Cache status"));
    }
}
