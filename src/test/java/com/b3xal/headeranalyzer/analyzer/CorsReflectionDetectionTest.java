package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.model.Confidence;
import com.b3xal.headeranalyzer.model.HeaderFinding;
import com.b3xal.headeranalyzer.model.Severity;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CorsReflectionDetectionTest {

    @Test
    void requiresExactOriginReflection() {
        List<HeaderFinding> findings = detect(Map.of(
                "Access-Control-Allow-Origin", "https://evil.example.attacker.test"),
                "https://evil.example");
        assertTrue(findings.isEmpty());
    }

    @Test
    void reflectedOriginWithoutCredentialsIsLowFirmSignal() {
        List<HeaderFinding> findings = detect(Map.of(
                "Access-Control-Allow-Origin", "https://evil.example"),
                "https://evil.example");
        assertEquals(1, findings.size());
        assertEquals(Severity.LOW, findings.get(0).severity);
        assertEquals(Confidence.FIRM, findings.get(0).confidence);
    }

    @Test
    void reflectedOriginWithCredentialsIsHighCertain() {
        List<HeaderFinding> findings = detect(Map.of(
                "Access-Control-Allow-Origin", "https://evil.example",
                "Access-Control-Allow-Credentials", "true"),
                "https://evil.example");
        assertEquals(1, findings.size());
        assertEquals(Severity.HIGH, findings.get(0).severity);
        assertEquals(Confidence.CERTAIN, findings.get(0).confidence);
        assertTrue(findings.get(0).evidence.contains("Vary: (absent)"));
        assertTrue(findings.get(0).description.contains("also lacks Vary: Origin"));
    }

    @Test
    void reflectionRequiresBodyBearing2xxResponse() {
        for (int status : new int[]{204, 301, 401, 403, 404, 405, 500, 503}) {
            assertTrue(detect(Map.of(
                    "Access-Control-Allow-Origin", "https://evil.example",
                    "Access-Control-Allow-Credentials", "true"),
                    "https://evil.example", status).isEmpty(), "status " + status);
        }
        assertEquals(1, detect(Map.of(
                "Access-Control-Allow-Origin", "https://evil.example",
                "Access-Control-Allow-Credentials", "true"),
                "https://evil.example", 201).size());
    }

    @Test
    void reflectedOriginWithVaryDoesNotClaimUnnecessarilyWarnAboutIt() {
        List<HeaderFinding> findings = detect(Map.of(
                "Access-Control-Allow-Origin", "https://evil.example",
                "Vary", "Accept-Encoding, Origin"), "https://evil.example");
        assertEquals(1, findings.size());
        assertTrue(findings.get(0).evidence.contains("Vary: Accept-Encoding, Origin"));
        assertFalse(findings.get(0).description.contains("also lacks Vary: Origin"));
    }

    @Test
    void everyCorsOriginBatteryVariantProducesAConfirmedFindingWhenReflected() {
        // These are the actual origin shapes used by corsProbe(), kept as fictional examples.
        // A response that echoes any of them exactly, with credentials enabled, is actionable.
        List<String> variants = List.of(
                "https://quimera-cors-probe.invalid",              // arbitrary origin
                "http://api.example.test",                         // HTTPS downgrade
                "null",                                            // opaque/null origin
                "https://api.example.test.quimera-cors-probe.invalid", // prefix bypass
                "https://api.example.testquimera-cors-probe.invalid",  // suffix bypass
                "https://random-quimera.api.example.test",         // arbitrary subdomain
                "https://api.example.tes",                         // truncated host
                "https://apixexample.test",                        // unescaped-dot regex
                "https://api.example.test_quimera-cors-probe.invalid" // underscore bypass
        );

        for (String origin : variants) {
            List<HeaderFinding> findings = detect(Map.of(
                    "Access-Control-Allow-Origin", origin,
                    "Access-Control-Allow-Credentials", "true"), origin);
            assertEquals(1, findings.size(), origin);
            assertEquals(Severity.HIGH, findings.get(0).severity, origin);
            assertEquals(Confidence.CERTAIN, findings.get(0).confidence, origin);
            assertTrue(findings.get(0).evidence.contains("Origin: " + origin), origin);
        }
    }

    @Test
    void rejectsWildcardAndStaticAllowedOriginsAsNonReflection() {
        for (String allowOrigin : List.of("*", "https://trusted.example.test", "null")) {
            assertTrue(detect(Map.of(
                    "Access-Control-Allow-Origin", allowOrigin,
                    "Access-Control-Allow-Credentials", "true"),
                    "https://quimera-cors-probe.invalid").isEmpty(), allowOrigin);
        }
    }

    private static List<HeaderFinding> detect(Map<String, String> headers, String origin) {
        return detect(headers, origin, 200);
    }

    private static List<HeaderFinding> detect(Map<String, String> headers, String origin, int status) {
        List<HeaderFinding> findings = new ArrayList<>();
        ActiveHeaderScanner.checkReflection(headers, status, origin, findings,
                "CORS test", "Test description.");
        return findings;
    }
}
