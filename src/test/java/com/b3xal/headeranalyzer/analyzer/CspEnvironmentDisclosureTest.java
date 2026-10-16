package com.b3xal.headeranalyzer.analyzer;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

class CspEnvironmentDisclosureTest {
    @Test void reports_qa_staging_and_localhost_shaped_hosts_but_not_public_hosts() {
        var findings = CspAnalyzer.analyze("frame-ancestors 'self' https://www.example.com " +
                "http://localhost.www-qa.example.com https://app-stg.example.com");
        assertTrue(findings.stream().anyMatch(f -> f.issueName.equals("CSP: development/internal hostname disclosed")
                && f.evidence.contains("localhost.www-qa.example.com") && f.evidence.contains("app-stg.example.com")));
        assertFalse(findings.stream().anyMatch(f -> f.evidence.contains("www.example.com")));
    }
}
