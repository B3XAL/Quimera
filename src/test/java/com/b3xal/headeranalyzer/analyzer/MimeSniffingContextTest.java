package com.b3xal.headeranalyzer.analyzer;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MimeSniffingContextTest {

    @Test
    void correctJavaScriptMimeDoesNotProduceNosniffFinding() {
        assertFalse(relevant("https://example.test/app.js", "script", "text/javascript"));
        assertFalse(relevant("https://example.test/app.mjs", null, "text/javascript; charset=utf-8"));
        assertFalse(relevant("https://example.test/app.cjs", "script", "application/javascript"));
        assertFalse(relevant("https://example.test/legacy.js", "script", "text/x-javascript"));
    }

    @Test
    void correctCssMimeDoesNotProduceNosniffFinding() {
        assertFalse(relevant("https://example.test/app.css", "style", "text/css"));
        assertFalse(relevant("https://example.test/app.css", null, "text/css; charset=utf-8"));
    }

    @Test
    void missingOrWrongMimeOnExecutableDestinationDoesProduceFinding() {
        assertTrue(relevant("https://example.test/app.js", "script", null));
        assertTrue(relevant("https://example.test/app.js", "script", "text/plain"));
        assertTrue(relevant("https://example.test/worker", "worker", "application/json"));
        assertTrue(relevant("https://example.test/app.css", "style", "text/html"));
        assertTrue(relevant("https://example.test/app.css", null, "application/octet-stream"));
    }

    @Test
    void destinationWinsOverMisleadingFileExtension() {
        assertFalse(relevant("https://example.test/app.js", "document", "text/plain"));
        assertFalse(relevant("https://example.test/theme.css", "fetch", "application/json"));
    }

    @Test
    void mimeTypesAlreadyBlockedForScriptsDoNotProduceRedundantFinding() {
        assertFalse(relevant("https://example.test/app.js", "script", "image/png"));
        assertFalse(relevant("https://example.test/app.js", "script", "audio/mpeg"));
        assertFalse(relevant("https://example.test/app.js", "script", "video/mp4"));
        assertFalse(relevant("https://example.test/app.js", "script", "text/csv"));
    }

    @Test
    void unrelatedResponsesDoNotProduceNosniffFinding() {
        assertFalse(relevant("https://example.test/", "document", "text/html"));
        assertFalse(relevant("https://example.test/api", "empty", "application/json"));
        assertFalse(relevant("https://example.test/download", null, null));
        assertFalse(HeaderAnalysisEngine.isMimeSniffingRelevant(
                Map.of("Content-Type", "text/plain"), Map.of("Sec-Fetch-Dest", "script"),
                "https://example.test/app.js", "POST"));
    }

    private static boolean relevant(String url, String destination, String contentType) {
        Map<String, String> response = contentType == null
                ? Map.of() : Map.of("Content-Type", contentType);
        Map<String, String> request = destination == null
                ? Map.of() : Map.of("Sec-Fetch-Dest", destination);
        return HeaderAnalysisEngine.isMimeSniffingRelevant(response, request, url, "GET");
    }
}
