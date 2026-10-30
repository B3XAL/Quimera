package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.config.QuimeraSettings;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SourceMapAnalyzerTest {
    private final HeaderAnalysisEngine engine =
            new HeaderAnalysisEngine(new RuleStore(null), new QuimeraSettings());

    @Test
    void confirmsAccessibleMapWithEmbeddedSources() {
        var findings = engine.analyze("https://example.test/assets/app.js.map", Map.of(), Map.of(), 200,
                "{\"version\":3,\"sources\":[\"webpack:///src/app.ts\"],\"sourcesContent\":[\"const x = 1;\"],\"mappings\":\"AAAA\"}", "GET")
                .findings;

        assertTrue(findings.stream().anyMatch(f ->
                f.issueName.equals("Public source map exposes embedded source content")
                        && f.confidence == com.b3xal.headeranalyzer.model.Confidence.CERTAIN));
    }

    @Test
    void reportsMapWithoutEmbeddedSourceAtLowerSeverity() {
        var findings = engine.analyze("https://example.test/assets/app.js.map?build=7", Map.of(), Map.of(), 200,
                "{\"version\":3,\"sources\":[\"src/app.ts\"],\"mappings\":\"AAAA\"}", "GET")
                .findings;

        assertTrue(findings.stream().anyMatch(f ->
                f.issueName.equals("Public source map accessible")
                        && f.severity == com.b3xal.headeranalyzer.model.Severity.LOW));
    }

    @Test
    void ignoresOpaqueEtagAndInvalidMapLookingResponses() {
        var etagOnly = engine.analyze("https://example.test/assets/photo.jpg", Map.of("ETag", "lcloud.js.map"),
                Map.of(), 200, "jpeg body", "GET").findings;
        var invalidMap = engine.analyze("https://example.test/assets/app.js.map", Map.of(), Map.of(), 200,
                "{\"version\":3,\"sources\":[\"src/app.ts\"]}", "GET").findings;

        assertEquals(0, etagOnly.stream().filter(f -> f.headerName.equals("(source map response)")).count());
        assertEquals(0, invalidMap.stream().filter(f -> f.headerName.equals("(source map response)")).count());
    }

    @Test
    void ignoresNonSuccessfulMapResponse() {
        var findings = engine.analyze("https://example.test/assets/app.js.map", Map.of(), Map.of(), 404,
                "{\"version\":3,\"sources\":[\"src/app.ts\"],\"mappings\":\"AAAA\"}", "GET").findings;

        assertTrue(findings.stream().noneMatch(f -> f.headerName.equals("(source map response)")));
    }
}
