package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.model.HeaderFinding;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Regression for false positives where a field merely ending in "key"/"token" (messageErrorKey,
 * USER_LANGUAGE_STORAGE_KEY, POPUP_STATUS_STORAGE_KEY, messageSuccessKey) carried a plain
 * configuration identifier value (an i18n key or storage-key name) and was reported as an
 * authentication secret. The loose field match fires only when a provider context marker is present
 * in the body (here firebaseio.com), which is exactly the real-world condition that produced these.
 */
class CredentialConfigIdentifierFalsePositiveTest {

    @Test
    void configIdentifierValueShapeRecognition() {
        for (String v : List.of("GENERAL.OPERATION_FAILED", "GENERAL.OPERATION_SUCCEEDED",
                "user_language", "popup_status", "FOO_BAR", "a.b.c", "cart.item.removed"))
            assertTrue(CredentialBodyAnalyzer.isConfigIdentifierValue(v), "should be a config identifier: " + v);

        // Non-identifier shapes (opaque/mixed, no word separators) must NOT be treated as config
        // identifiers. These are deliberately synthetic and provider-pattern-free so the public
        // repo's secret push-protection never mistakes a test fixture for a real key.
        for (String v : List.of("Zx9Qw3ErTy", "9c8b7a6f5e4d3c2b1a09", "en-US", "token", "abc123"))
            assertFalse(CredentialBodyAnalyzer.isConfigIdentifierValue(v), "should NOT be a config identifier: " + v);
    }

    @Test
    void storageAndMessageKeyIdentifiersAreNotReportedAsSecrets() {
        String body = "var cfg={db:\"https://demo.firebaseio.com\"};"
                + "this.messageErrorKey=\"GENERAL.OPERATION_FAILED\";"
                + "this.messageSuccessKey=\"GENERAL.OPERATION_SUCCEEDED\";"
                + "this.USER_LANGUAGE_STORAGE_KEY=\"user_language\";"
                + "this.POPUP_STATUS_STORAGE_KEY=\"popup_status\";";
        List<HeaderFinding> findings = CredentialBodyAnalyzer.analyze(body, "text/javascript", "response", null);
        assertTrue(findings.stream().noneMatch(f ->
                        f.evidence.contains("OPERATION_FAILED") || f.evidence.contains("OPERATION_SUCCEEDED")
                        || f.evidence.contains("user_language") || f.evidence.contains("popup_status")),
                "config identifiers under *Key fields must not be reported as credentials: " + findings);
    }

    @Test
    void realOpaqueSecretUnderKeyFieldIsStillReported() {
        // Same provider context, but a genuine high-entropy secret value must remain detected
        // (the fix must not silently suppress real leaks).
        String secret = "opaque-serverkey-9f3b2a7c1d4e";
        String body = "var cfg={db:\"https://demo.firebaseio.com\"};"
                + "this.serverKey=\"" + secret + "\";";
        List<HeaderFinding> findings = CredentialBodyAnalyzer.analyze(body, "text/javascript", "response", null);
        assertTrue(findings.stream().anyMatch(f -> f.evidence.contains(secret)),
                "a genuine opaque secret under serverKey must still be reported: " + findings);
    }
}
