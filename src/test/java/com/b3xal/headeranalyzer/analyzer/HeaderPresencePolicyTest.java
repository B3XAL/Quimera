package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.config.QuimeraSettings;
import com.b3xal.headeranalyzer.model.UrlAnalysisResult;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HeaderPresencePolicyTest {

    private final HeaderAnalysisEngine engine =
            new HeaderAnalysisEngine(new RuleStore(null), new QuimeraSettings());

    @Test
    void absenceOnlyReportsHeadersThatRemainIntentionalFindings() {
        UrlAnalysisResult result = engine.analyze("https://example.test/account",
                Map.of("Content-Type", "text/html"), 200, "<html></html>", "GET");

        assertTrue(has(result, "Missing Content Security Policy"));
        assertTrue(has(result, "Missing HTTP Strict Transport Security"));
        assertTrue(has(result, "Missing Clickjacking Protection"));
        assertFalse(has(result, "Missing Referrer Policy"));
        assertFalse(has(result, "Missing Permissions Policy"));
        assertFalse(has(result, "Missing Cross-Origin Opener Policy"));
        assertFalse(has(result, "HSTS does not cover subdomains"));
    }

    @Test
    void deepCspAnalysisStillRunsWhileMissingCspRemainsEnabled() {
        UrlAnalysisResult result = engine.analyze("https://example.test/account",
                Map.of("Content-Type", "text/html",
                        "Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'"),
                200, "<html></html>", "GET");

        assertFalse(has(result, "Missing Content Security Policy"));
        assertTrue(result.findings.stream().anyMatch(f -> f.issueName.startsWith("CSP:")));
    }

    @Test
    void validXfoSuppressesDuplicateMissingFrameAncestorsFinding() {
        UrlAnalysisResult result = engine.analyze("https://example.test/account",
                Map.of("Content-Type", "text/html", "X-Frame-Options", "DENY",
                        "Content-Security-Policy", "default-src 'self'"),
                200, "<html></html>", "GET");

        assertFalse(has(result, "Missing Clickjacking Protection"));
        assertFalse(has(result, "CSP: frame-ancestors directive missing"));
    }

    private static boolean has(UrlAnalysisResult result, String issueName) {
        return result.findings.stream().anyMatch(f -> issueName.equals(f.issueName));
    }
}
