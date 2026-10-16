package com.b3xal.headeranalyzer.analyzer;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CorsOriginConstructionTest {

    @Test
    void downgradeProbeOnlyExistsForHttpsTargets() {
        assertEquals("http://api.example.test",
                ActiveHeaderScanner.httpDowngradeOrigin("https://api.example.test/data"));
        assertNull(ActiveHeaderScanner.httpDowngradeOrigin("http://api.example.test/data"));
    }

    @Test
    void domainBypassVariantsAreSkippedForIpsAndLocalhost() {
        assertTrue(ActiveHeaderScanner.isDomainHost("api.example.test"));
        assertFalse(ActiveHeaderScanner.isDomainHost("127.0.0.1"));
        assertFalse(ActiveHeaderScanner.isDomainHost("::1"));
        assertFalse(ActiveHeaderScanner.isDomainHost("localhost"));
    }

    @Test
    void subdomainAndConcatenationOriginsAreDifferentFromTheTarget() {
        assertEquals("https://random-quimera.api.example.test",
                ActiveHeaderScanner.fakeSubdomainOrigin("api.example.test"));
        assertEquals("https://api.example.testquimera-cors-probe.invalid",
                ActiveHeaderScanner.concatenationBypassOrigin("api.example.test"));
    }
}
