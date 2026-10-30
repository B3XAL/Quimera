package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.model.Severity;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IdentityMetadataAnalyzerTest {

    @Test
    void reportsOnlyExplicitIdentityMetadataHeadersAsInformation() {
        var findings = IdentityMetadataAnalyzer.analyzeResponseHeaders(Map.of(
                "X-Tenant-ID", "stories", "X-User-ID", "cc6ecd05d67b4bacaad9cf1d0694d83a",
                "X-Roles", "admin, reviewer", "X-Request-ID", "a1b2c3", "Traceparent", "00-abc"), Map.of());

        assertEquals(3, findings.size());
        assertTrue(findings.stream().allMatch(f -> f.severity == Severity.INFORMATION));
        assertTrue(findings.stream().anyMatch(f -> f.headerName.equals("X-Tenant-ID")));
        assertTrue(findings.stream().anyMatch(f -> f.headerName.equals("X-User-ID")));
        assertTrue(findings.stream().anyMatch(f -> f.headerName.equals("X-Roles")));
    }

    @Test
    void skipsPlaceholdersAndReflectedRequestIdentityHeaders() {
        var findings = IdentityMetadataAnalyzer.analyzeResponseHeaders(Map.of(
                "X-Tenant-ID", "stories", "X-User-ID", "redacted"), Map.of("X-Tenant-ID", "stories"));
        assertTrue(findings.isEmpty());
    }
}
