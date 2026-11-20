package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.config.QuimeraSettings;
import com.b3xal.headeranalyzer.model.HeaderFinding;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

import java.util.Map;

class CspEnvironmentDisclosureTest {
    @Test void reports_qa_staging_and_localhost_shaped_hosts_but_not_public_hosts() {
        var findings = CspAnalyzer.analyze("frame-ancestors 'self' https://www.example.com " +
                "http://localhost.www-qa.example.com https://app-stg.example.com");
        assertTrue(findings.stream().anyMatch(f -> f.issueName.equals("CSP: development/internal hostname disclosed")
                && f.evidence.contains("localhost.www-qa.example.com") && f.evidence.contains("app-stg.example.com")));
        assertFalse(findings.stream().anyMatch(f -> f.evidence.contains("www.example.com")));
    }

    @Test void retainsEnvironmentDisclosureOnJsonApiResponses() {
        HeaderAnalysisEngine engine = new HeaderAnalysisEngine(new RuleStore(null), new QuimeraSettings());
        var result = engine.analyze("https://api.example.test/v1/profile", Map.of(
                "Content-Type", "application/json",
                "Content-Security-Policy", "connect-src 'self' https://api-qa.example.test"),
                Map.of(), 200, "{}", "GET");

        assertTrue(result.findings.stream().anyMatch(f ->
                f.issueName.equals("CSP: development/internal hostname disclosed")
                        && f.category == HeaderFinding.Category.INFORMATION_DISCLOSURE
                        && f.evidence.contains("api-qa.example.test")));
    }
}
