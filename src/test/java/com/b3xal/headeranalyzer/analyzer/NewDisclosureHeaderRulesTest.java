package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.config.QuimeraSettings;
import com.b3xal.headeranalyzer.model.Severity;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NewDisclosureHeaderRulesTest {
    private final HeaderAnalysisEngine engine =
            new HeaderAnalysisEngine(new RuleStore(null), new QuimeraSettings());

    private long countFor(Map<String, String> headers, String headerName) {
        var result = engine.analyze("https://example.test/x", headers, Map.of(), 200, "<html></html>", "GET");
        return result.findings.stream().filter(f -> f.headerName.equalsIgnoreCase(headerName)).count();
    }

    @Test
    void sourceMapAndLegacyXSourceMapBothFire() {
        assertEquals(1, countFor(Map.of("SourceMap", "/static/app.js.map"), "SourceMap"));
        assertEquals(1, countFor(Map.of("X-SourceMap", "/static/app.js.map"), "X-SourceMap"));
    }

    @Test
    void magentoCacheDebugFires() {
        assertEquals(1, countFor(Map.of("X-Magento-Cache-Debug", "HIT"), "X-Magento-Cache-Debug"));
    }

    @Test
    void kongLatencyHeadersFire() {
        assertEquals(1, countFor(Map.of("X-Kong-Proxy-Latency", "1"), "X-Kong-Proxy-Latency"));
        assertEquals(1, countFor(Map.of("X-Kong-Upstream-Latency", "12"), "X-Kong-Upstream-Latency"));
        assertEquals(1, countFor(Map.of("X-Kong-Response-Latency", "3"), "X-Kong-Response-Latency"));
    }

    /** The regression this guards against: Via's mandatory leading protocol-version token
     * ("1.1 ...", RFC 7230) must NOT by itself be mistaken for a product version, only an actual
     * name/version pair (e.g. "kong/3.4.1") should escalate to MEDIUM. */
    @Test
    void viaWithBareProxyNameStaysInformationNotFalselyFlaggedAsVersioned() {
        var result = engine.analyze("https://example.test/x",
                Map.of("Via", "1.1 vegur"), Map.of(), 200, "<html></html>", "GET");
        var findings = result.findings.stream()
                .filter(f -> f.headerName.equalsIgnoreCase("Via")).toList();
        assertEquals(1, findings.size());
        assertEquals(Severity.INFORMATION, findings.get(0).severity);
    }

    @Test
    void viaWithRealProductVersionEscalatesToMedium() {
        var result = engine.analyze("https://example.test/x",
                Map.of("Via", "1.1 kong/3.4.1"), Map.of(), 200, "<html></html>", "GET");
        var findings = result.findings.stream()
                .filter(f -> f.headerName.equalsIgnoreCase("Via")).toList();
        assertEquals(1, findings.size());
        assertEquals(Severity.MEDIUM, findings.get(0).severity);
        assertTrue(findings.get(0).issueName.toLowerCase().contains("version"));
    }
}
