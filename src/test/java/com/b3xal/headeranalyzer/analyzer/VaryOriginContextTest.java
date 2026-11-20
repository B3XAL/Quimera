package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.config.QuimeraSettings;
import com.b3xal.headeranalyzer.model.UrlAnalysisResult;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VaryOriginContextTest {
    private static final String ORIGIN = "https://trusted-partner.example";
    private final HeaderAnalysisEngine engine =
            new HeaderAnalysisEngine(new RuleStore(null), new QuimeraSettings());

    @Test
    void reportsMissingVaryOnSuccessfulCacheableCorsResponse() {
        UrlAnalysisResult result = analyze(200, "GET", null);
        assertTrue(hasMissingVary(result));
    }

    @Test
    void suppressesMissingVaryForQuimeraCorsProbeOwnedByActiveFinding() {
        assertFalse(hasMissingVary(analyze(200, "GET", null,
                "https://example.test_quimera-cors-probe.invalid")));
    }

    @Test
    void suppressesMissingVaryOnErrorAndMethodResponses() {
        for (int status : new int[]{401, 404, 405, 500, 503}) {
            assertFalse(hasMissingVary(analyze(status, "GET", null)), "status " + status);
        }
        assertFalse(hasMissingVary(analyze(200, "OPTIONS", null)));
        assertFalse(hasMissingVary(analyze(200, "POST", null)));
    }

    @Test
    void suppressesMissingVaryWhenSharedCachingIsForbidden() {
        assertFalse(hasMissingVary(analyze(200, "GET", "private")));
        assertFalse(hasMissingVary(analyze(200, "GET", "no-store")));
        assertFalse(hasMissingVary(analyze(200, "GET", "no-cache")));
    }

    private UrlAnalysisResult analyze(int status, String method, String cacheControl) {
        return analyze(status, method, cacheControl, ORIGIN);
    }

    private UrlAnalysisResult analyze(int status, String method, String cacheControl, String origin) {
        Map<String, String> response = new LinkedHashMap<>();
        response.put("Content-Type", "application/json");
        response.put("Access-Control-Allow-Origin", origin);
        if (cacheControl != null) response.put("Cache-Control", cacheControl);
        return engine.analyze("https://example.test/api", response,
                Map.of("Origin", origin), status, "{\"ok\":true}", method);
    }

    private static boolean hasMissingVary(UrlAnalysisResult result) {
        return result.findings.stream().anyMatch(f ->
                f.issueName.equals("Missing Vary: Origin on dynamic CORS response"));
    }
}
