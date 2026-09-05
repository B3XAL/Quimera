package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.config.QuimeraSettings;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Regression coverage for a real bug: QuimeraHttpHandler, HeaderPassiveScanner and BulkAnalyzer
 * each skipped the ENTIRE analysis for static/binary content types (images, fonts, media,
 * archives), only re-adding a narrow cache-key-only check afterwards. Real traffic (a WordPress
 * .webp image behind Varnish) proved this dropped genuine infrastructure disclosures
 * (X-Varnish-Ip/X-Varnish-Port/X-Served-By) that have nothing to do with cache keys.
 *
 * The actual fix lives in each of those three call sites (they now call the cheap 4-arg
 * engine.analyze(url, headers, status, method) instead of skipping entirely), which cannot be
 * exercised here without a full MontoyaApi mock. What CAN be verified directly, and is the load-
 * bearing assumption the fix depends on, is that engine.analyze() + applyContextFilter genuinely
 * keep INFORMATION_DISCLOSURE findings for asset content types instead of stripping them.
 */
class AssetContentTypeDisclosureTest {
    private final HeaderAnalysisEngine engine =
            new HeaderAnalysisEngine(new RuleStore(null), new QuimeraSettings());

    /** The exact real-world header set that exposed the bug, condensed. */
    private static final Map<String, String> WEBP_RESPONSE_HEADERS = Map.of(
            "Content-Type", "image/webp",
            "Via", "1.1 varnish (Varnish/7.1)",
            "X-Cache", "HIT",
            "X-Served-By", "cflinstitprdlamp02",
            "X-Varnish", "9770098 7052197",
            "X-Varnish-Ip", "10.0.25.16",
            "X-Varnish-Port", "81",
            "Strict-Transport-Security", "max-age=15768000");

    @Test
    void thisResponseIsActuallyExcludedFromTheExpensivePipelineByDefault() {
        assertFalse(new QuimeraSettings().shouldAnalyze("image/webp",
                "https://example.test/wp-content/uploads/2025/12/Fichier-6picto2-scaled.webp"));
    }

    @Test
    void cheapHeaderOnlyAnalysisStillSurfacesBackendDisclosuresOnAnImageResponse() {
        var result = engine.analyze(
                "https://example.test/wp-content/uploads/2025/12/Fichier-6picto2-scaled.webp",
                WEBP_RESPONSE_HEADERS, 200, "GET");

        List<String> disclosedHeaders = result.findings.stream().map(f -> f.headerName).toList();
        assertTrue(disclosedHeaders.contains("X-Varnish-Ip"), disclosedHeaders.toString());
        assertTrue(disclosedHeaders.contains("X-Varnish-Port"), disclosedHeaders.toString());
        assertTrue(disclosedHeaders.contains("X-Served-By"), disclosedHeaders.toString());
        assertTrue(disclosedHeaders.contains("X-Varnish"), disclosedHeaders.toString());

        // The "missing HSTS" mandatory check must NOT fire here even though the header set above
        // happens to include it: this is a browser-rendering-irrelevant asset response, not proof
        // applyContextFilter stopped filtering anything document-specific.
        assertFalse(disclosedHeaders.contains("Content-Security-Policy"),
                "missing-CSP must stay suppressed for image responses: " + disclosedHeaders);
    }

    /** Regression for a second, related bug found live: the header-only 4-arg analyze() overload
     * (used for exactly these filtered content types) never called applyMimeAndCacheContext, the
     * pass that uses Sec-Fetch-Dest/URL-extension/MIME to decide whether a missing nosniff header
     * is real. That meant "Missing X-Content-Type-Options" fired on every single image/font/media
     * response the moment they started being header-analyzed at all (the fix above), even though
     * nosniff has no effect on non-script/style destinations, real, confirmed noise on an
     * asset-heavy page. */
    @Test
    void missingNosniffDoesNotFireOnAPlainImageResponseGoingThroughTheCheapPath() {
        var result = engine.analyze(
                "https://example.test/wp-content/uploads/2025/12/Fichier-6picto2-scaled.webp",
                WEBP_RESPONSE_HEADERS, 200, "GET");

        List<String> disclosedHeaders = result.findings.stream().map(f -> f.headerName).toList();
        assertFalse(disclosedHeaders.contains("X-Content-Type-Options"),
                "missing nosniff must stay suppressed for a plain image response: " + disclosedHeaders);
    }

    /** Same cheap path, but for an actual .js file with no Content-Type at all (URL-extension
     * fallback inside isMimeSniffingRelevant, since this overload has no request headers to read
     * a real Sec-Fetch-Dest from): nosniff IS relevant there, must still fire. */
    @Test
    void missingNosniffStillFiresOnAJavaScriptResponseGoingThroughTheCheapPath() {
        var result = engine.analyze(
                "https://example.test/assets/app.js",
                Map.of("Strict-Transport-Security", "max-age=15768000"), 200, "GET");

        List<String> disclosedHeaders = result.findings.stream().map(f -> f.headerName).toList();
        assertTrue(disclosedHeaders.contains("X-Content-Type-Options"), disclosedHeaders.toString());
    }

    /** The same generic-name attribution risk X-Served-By had: found by auditing every other
     * presenceOnly() vendor shortcut in TechFingerprinter after the X-Served-By counter-example,
     * not from a second independent real-traffic sighting. */
    @Test
    void timerOnlyClaimsFastlyForFastlyShapedValues() {
        var fastlyShaped = TechFingerprinter.analyze(Map.of("X-Timer", "S1652738226.434538,VS0,VE2"));
        assertTrue(fastlyShaped.stream().anyMatch(t -> t.product.equals("Fastly")), fastlyShaped.toString());

        var customTimer = TechFingerprinter.analyze(Map.of("X-Timer", "42ms"));
        assertFalse(customTimer.stream().anyMatch(t -> t.product.equals("Fastly")), customTimer.toString());
    }

    @Test
    void servedByOnlyClaimsFastlyForFastlyShapedNodeNames() {
        var fastlyShaped = TechFingerprinter.analyze(Map.of("X-Served-By", "cache-lcy1234-LCY"));
        assertTrue(fastlyShaped.stream().anyMatch(t -> t.product.equals("Fastly")), fastlyShaped.toString());

        var customBackend = TechFingerprinter.analyze(Map.of("X-Served-By", "cflinstitprdlamp02"));
        assertFalse(customBackend.stream().anyMatch(t -> t.product.equals("Fastly")), customBackend.toString());
    }
}
