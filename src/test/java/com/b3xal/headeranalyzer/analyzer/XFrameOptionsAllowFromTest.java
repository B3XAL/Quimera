package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.config.QuimeraSettings;
import static org.junit.jupiter.api.Assertions.*;
import java.util.Map;
import org.junit.jupiter.api.Test;

class XFrameOptionsAllowFromTest {
    @Test void allowFromGetsOne_precise_diagnostic_not_generic_duplicate() {
        var result = new HeaderAnalysisEngine(new RuleStore(null), new QuimeraSettings()).analyze(
                "https://example.test/account", Map.of("Content-Type", "text/html",
                "X-Frame-Options", "ALLOW-FROM https://one.test https://two.test"), Map.of(),
                (short) 200, "<form></form>", "GET", true, "");
        assertTrue(result.findings.stream().anyMatch(f -> f.issueName.equals("X-Frame-Options uses deprecated ALLOW-FROM")));
        assertFalse(result.findings.stream().anyMatch(f -> f.issueName.equals("X-Frame-Options misconfigured")));
    }
}
