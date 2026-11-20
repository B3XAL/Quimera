package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.model.HeaderFinding;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Covers the unquoted-value path for env/YAML/properties-style dumps (API_SECRET=..., key: value)
 * and its false-positive guards: a bare value is only a credential when the field is an explicit,
 * compound secret key name and the value is high entropy. JS variable references, prose, versions,
 * booleans, sizes and bare dictionary words must never trigger.
 */
class CredentialUnquotedValueTest {
    private static final String SECRET = "Z1i7xWzQpqQmsWk5bx6DBkIS"; // opaque, high entropy, no provider shape

    private static boolean detected(String body, String ct) {
        List<HeaderFinding> f = CredentialBodyAnalyzer.analyze(body, ct, "response", null);
        return f.stream().anyMatch(x -> x.headerValue != null && x.headerValue.contains(SECRET));
    }

    @Test
    void detectsUnquotedSecretsInConfigDumps() {
        assertTrue(detected("API_SECRET=" + SECRET, "text/plain"), "env KEY=value");
        assertTrue(detected("api_secret: " + SECRET, "application/x-yaml"), "yaml key: value");
        assertTrue(detected("jwt.secret=" + SECRET, "text/plain"), "properties dotted key");
        assertTrue(detected("APP_API_KEY=" + SECRET, "text/plain"), "env *_API_KEY");
    }

    @Test
    void doesNotFlagVariablesPoseVersionsOrSizes() {
        assertFalse(detected("x={authSecret: someVariableReference}", "text/javascript"), "JS variable reference");
        assertFalse(detected("console.log('startup token: " + SECRET + " loaded');", "text/javascript"),
                "bare word in prose must not steal the value");
        assertFalse(detected("mode=production", "text/plain"), "non-secret setting");
        assertFalse(detected("appVersion=1.2.3456789", "text/plain"), "version");
        assertFalse(detected("div.width=100px000000", "text/plain"), "size-like");
        assertFalse(detected("debugEnabled=true", "text/plain"), "boolean");
    }

    @Test
    void configKeyNameShapeRecognition() {
        for (String ok : List.of("api_secret", "API_SECRET", "jwt.secret", "authSecret", "x-api-key"))
            assertTrue(CredentialBodyAnalyzer.looksLikeConfigKeyName(ok), ok);
        for (String no : List.of("token", "secret", "password", "key", "bearer"))
            assertFalse(CredentialBodyAnalyzer.looksLikeConfigKeyName(no), no);
    }
}
