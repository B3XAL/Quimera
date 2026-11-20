package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.model.HeaderFinding;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** Edge cases and false-positive guards for credential body detection, grounded in observed behavior. */
class CredentialDetectionEdgeTest {
    private static List<HeaderFinding> scan(String body) {
        return CredentialBodyAnalyzer.analyze(body, "text/javascript", "response", null);
    }
    private static long hits(String body) {
        return scan(body).stream().filter(f -> f.headerValue != null).count();
    }

    @Test
    void publicBrowserKeysAndPlaceholdersAreNotReported() {
        assertEquals(0, hits("var k='pk_live_0123456789abcdefABCDEFGH'"), "Stripe publishable key is public");
        assertEquals(0, hits("mapboxToken=`pk.eyJhIjoiYiJ9.abcDEF`"), "Mapbox public token");
        assertEquals(0, hits("{apiKey:``}"), "empty value");
        assertEquals(0, hits("{apiSecret:`short12`}"), "value under 8 chars");
        assertEquals(0, hits("var google_recaptcha_key='6Lexamplepublicsitekey1234567890abcd'"),
                "reCAPTCHA public site key");
    }

    @Test
    void identifierShapedValuesUnderNonSecretFieldsAreNotReported() {
        assertEquals(0, hits("{id:`550e8400-e29b-41d4-a716-446655440000`}"), "UUID under id");
        assertEquals(0, hits("{requestId:`req-abc-123-def-456-ghi-789`}"), "request id");
        assertEquals(0, hits("{version:`10.4.2-beta.20260101`}"), "version string");
    }

    @Test
    void realSecretsAreReported() {
        assertEquals(1, hits("{\\\"apiSecret\\\":\\\"Z1i7xWzQpqQmsWk5bx6DBkIS\\\"}"), "escaped-JSON secret");
        assertEquals(1, hits("{apiKey:'Z1i7xWzQpqQmsWk5bx6DBkIS'}"), "single-quoted secret");
        assertTrue(hits("API_SECRET=Z1i7xWzQpqQmsWk5bx6DBkIS\nJWT_SECRET=Kp9mNq2wRt5vXy8zBd3fGh6j") >= 2,
                "two distinct high-entropy env secrets both reported");
    }

    @Test
    void providerSignatureBoundariesDoNotOverMatch() {
        // Wrong length / wrong context must not fire the prefixed-provider signatures.
        assertEquals(0, hits("var s='npm_tooShort';"), "npm token wrong length");
        assertEquals(0, hits("var s='AKIANOTLONGENOUGH';"), "AWS key id wrong length");
        assertEquals(0, hits("var s='ghp_onlytwentychars0000';"), "GitHub token wrong length");
    }
}
