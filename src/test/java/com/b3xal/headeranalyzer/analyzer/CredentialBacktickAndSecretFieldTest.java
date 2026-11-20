package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.model.HeaderFinding;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Regression for secrets missed inside JS bundles that assign values with template-literal
 * backticks (`authSecret:` + backtick + value + backtick) and for secret field names that end in a
 * generic "secret" suffix (authSecret) rather than one of the explicitly enumerated suffixes.
 * Values here are synthetic and deliberately NOT real provider-key shapes, so the public repo's
 * secret push-protection does not mistake a fixture for a live key.
 */
class CredentialBacktickAndSecretFieldTest {

    private static String reported(List<HeaderFinding> f) {
        return f.stream().map(x -> x.issueName + " :: " + x.headerValue).reduce("", (a, b) -> a + "\n" + b);
    }

    @Test
    void backtickDelimitedSecretIsDetected() {
        String body = "var l_=class{commonSettings={authClientId:`app-web-int`,"
                + "authSecret:`Z1i7xWzQpqQmsWk5bx6DBkIS`};};";
        List<HeaderFinding> f = CredentialBodyAnalyzer.analyze(body, "text/javascript", "response", null);
        assertTrue(f.stream().anyMatch(x -> x.headerValue != null
                        && x.headerValue.contains("Z1i7xWzQpqQmsWk5bx6DBkIS")),
                "backtick-delimited authSecret must be detected: " + reported(f));
        // A public client id is not a secret and must not be reported.
        assertTrue(f.stream().noneMatch(x -> x.headerValue != null && x.headerValue.contains("app-web-int")),
                "authClientId (public) must not be reported: " + reported(f));
    }

    @Test
    void genericSecretSuffixIsACredentialFieldWithoutAProvider() {
        // No provider marker anywhere in the body: authSecret must still classify on its name.
        assertTrue(CredentialProviderCatalog.isCredentialField("authSecret", "no provider context here"));
        assertTrue(CredentialProviderCatalog.isCredentialField("sharedSecret", "x"));
        // But a non-secret field must not become a credential field just from the suffix rules.
        assertFalse(CredentialProviderCatalog.isCredentialField("authClientId", "x"));
        assertFalse(CredentialProviderCatalog.isCredentialField("messageErrorKey", "no provider here"));
    }

    @Test
    void backtickApiKeyFieldIsDetected() {
        String body = "mobileSettings={uptimeRobotReadOnlyApiKey:`ur1658asdffsf15f`,projectShortId:`is8h`};";
        List<HeaderFinding> f = CredentialBodyAnalyzer.analyze(body, "text/javascript", "response", null);
        assertTrue(f.stream().anyMatch(x -> x.headerValue != null && x.headerValue.contains("ur1658asdffsf15f")),
                "backtick-delimited *ApiKey must be detected: " + reported(f));
    }

    @Test
    void backtickGoogleMapsKeyFieldIsDetected() {
        // Opaque synthetic value (not an AIza... shape, to stay push-protection-safe); the
        // googleMaps* field under a Google-Maps provider context is enough to classify it.
        String body = "webSettings={googleMapsDefaultKey:`opaque-maps-key-9f3b2a7c1d4e5f`,"
                + "defaultTimeZone:`Europe/Berlin`};var u='maps.googleapis.com';";
        List<HeaderFinding> f = CredentialBodyAnalyzer.analyze(body, "text/javascript", "response", null);
        assertTrue(f.stream().anyMatch(x -> x.headerValue != null
                        && x.headerValue.contains("opaque-maps-key-9f3b2a7c1d4e5f")),
                "backtick-delimited googleMapsDefaultKey must be detected: " + reported(f));
    }

    @Test
    void oversizedBodyStillScansItsLeadingPrefix() {
        // A secret near the top of a body larger than MAX_BODY must still be found (prefix scan),
        // instead of the whole body being skipped.
        String secret = "authSecret:`Z1i7xWzQpqQmsWk5bx6DBkIS`;";
        String body = secret + "x".repeat(6_000_000);
        List<HeaderFinding> f = CredentialBodyAnalyzer.analyze(body, "text/javascript", "response", null);
        assertTrue(f.stream().anyMatch(x -> x.headerValue != null
                        && x.headerValue.contains("Z1i7xWzQpqQmsWk5bx6DBkIS")),
                "secret in the first MAX_BODY bytes of an oversized body must still be detected");
    }
}
