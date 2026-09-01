package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.model.Confidence;
import com.b3xal.headeranalyzer.model.HeaderFinding;
import com.b3xal.headeranalyzer.model.Severity;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
    }

    private static List<HeaderFinding> detect(Map<String, String> headers, String origin) {
        List<HeaderFinding> findings = new ArrayList<>();
        ActiveHeaderScanner.checkReflection(headers, origin, findings,
                "CORS test", "Test description.");
        return findings;
    }
}
