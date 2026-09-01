package com.b3xal.headeranalyzer.analyzer;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HeaderAnalysisEngineUrlTest {
    @Test
    void normalizesUrlWithoutQueryOrFragmentAndKeepsNonDefaultPort() {
        assertEquals("https://example.test:8443/a/b",
                HeaderAnalysisEngine.normalizeUrl("https://example.test:8443/a/b?q=1#part"));
        assertEquals("https://example.test/", HeaderAnalysisEngine.normalizeUrl("https://example.test"));
    }

    @Test
    void extractsHostAndPath() {
        assertEquals("example.test", HeaderAnalysisEngine.extractHost("https://example.test/a"));
        assertEquals("/a", HeaderAnalysisEngine.extractPath("https://example.test/a?q=1"));
    }

    @Test
    void malformedInputFallsBackSafely() {
        assertEquals("not a url", HeaderAnalysisEngine.normalizeUrl("not a url"));
        assertEquals("not a url", HeaderAnalysisEngine.extractHost("not a url"));
        assertEquals("/", HeaderAnalysisEngine.extractPath("not a url"));
    }

    @Test
    void identifiesOnlyQuimeraControlPathAndChildren() {
        assertTrue(HeaderAnalysisEngine.isQuimeraInternalUrl("http://127.0.0.1:8199/quimera"));
        assertTrue(HeaderAnalysisEngine.isQuimeraInternalUrl(
                "http://127.0.0.1:8199/quimera/v1/ingest?source=browser"));
        assertTrue(HeaderAnalysisEngine.isQuimeraInternalUrl("https://example.test/QUIMERA/v1/ping"));
        assertFalse(HeaderAnalysisEngine.isQuimeraInternalUrl("https://example.test/quimera-app"));
        assertFalse(HeaderAnalysisEngine.isQuimeraInternalUrl("https://example.test/app/quimera"));
    }
}
