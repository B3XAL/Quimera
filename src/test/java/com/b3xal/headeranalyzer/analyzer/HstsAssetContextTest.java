package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.config.QuimeraSettings;
import com.b3xal.headeranalyzer.model.UrlAnalysisResult;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * HSTS is a host-level transport policy, so "missing HSTS" is noise on a static asset response
 * (JS/CSS/image/font). It must still be reported on an HTML document. nosniff must NOT be dropped
 * on assets, where MIME sniffing is exactly what matters.
 */
class HstsAssetContextTest {
    private final RuleStore rules = new RuleStore(null);
    private final HeaderAnalysisEngine engine = new HeaderAnalysisEngine(rules, new QuimeraSettings());

    private UrlAnalysisResult analyze(String url, String contentType, String body) {
        return engine.analyze(url, Map.of("Content-Type", contentType), Map.of(), 200, body, "GET");
    }
    private boolean has(UrlAnalysisResult r, String header) {
        return r.findings.stream().anyMatch(f -> f.headerName.equalsIgnoreCase(header));
    }

    @Test
    void missingHstsIsReportedOnHtmlDocument() {
        assertTrue(has(analyze("https://example.test/page", "text/html", "<html><body>x</body></html>"),
                "Strict-Transport-Security"));
    }

    @Test
    void missingHstsIsNotReportedOnStaticAssets() {
        assertFalse(has(analyze("https://example.test/app.js", "application/javascript", "var a=1;"),
                "Strict-Transport-Security"), "missing HSTS on JS is noise");
        assertFalse(has(analyze("https://example.test/app.css", "text/css", "a{color:red}"),
                "Strict-Transport-Security"), "missing HSTS on CSS is noise");
    }

    @Test
    void imageAndFontAssetsDoNotGetMissingHsts() {
        assertFalse(has(analyze("https://example.test/logo.png", "image/png", ""),
                "Strict-Transport-Security"), "missing HSTS on image is noise");
        assertFalse(has(analyze("https://example.test/f.woff2", "font/woff2", ""),
                "Strict-Transport-Security"), "missing HSTS on font is noise");
    }

    @Test
    void missingHstsStillReportedOnJsonApiResponse() {
        // API responses are on the same origin and legitimately represent the host transport
        // posture; HSTS is not suppressed there (only on static assets).
        assertTrue(has(analyze("https://example.test/v1/data", "application/json", "{\"ok\":true}"),
                "Strict-Transport-Security"), "HSTS still evaluated on API responses");
    }
}
