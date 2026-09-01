package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.config.CookiesAndAuthConfig;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class GoogleApiKeyUrlDetectionTest {
    private static final String KEY = "AIza12345678901234567890123456789012345";

    @Test
    void detectsGoogleKeyEvenUnderGenericQueryParameter() {
        var findings = AuthHeaderAnalyzer.analyze(
                "https://example.test/app?config=" + KEY, Map.of(), config());

        var finding = findings.stream()
                .filter(f -> f.issueName.equals("Google API key exposed in URL query string"))
                .findFirst().orElseThrow();
        assertEquals(KEY, finding.headerValue);
        assertTrue(finding.evidence.contains("config=" + KEY));
    }

    @Test
    void doesNotDuplicateGoogleKeyAsGenericQueryToken() {
        var findings = AuthHeaderAnalyzer.analyze(
                "https://example.test/app?api_key=" + KEY, Map.of(), config());

        assertEquals(1, findings.stream().filter(f -> f.headerValue.equals(KEY)).count());
    }

    private static CookiesAndAuthConfig config() {
        return new CookiesAndAuthConfig(60, true, true, true, List.of(), List.of(),
                true, true, true, true, true, true, true, true,
                List.of(), List.of(), true);
    }
}
