package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.model.HeaderFinding;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Real false positives reported from production minified bundles: key-ish field names assigned a
 * plain word, a template-literal key, a member expression or a template interpolation must not be
 * reported as credentials, while genuine secrets in the same bundles still are.
 */
class CredentialMinifiedBundleFalsePositiveTest {

    private static List<HeaderFinding> scan(String body) {
        return CredentialBodyAnalyzer.analyze(body, "text/javascript", "response", null);
    }
    private static boolean any(String body) {
        return scan(body).stream().anyMatch(f -> f.headerValue != null);
    }

    @Test
    void keyFieldsWithPlainOrCodeValuesAreNotCredentials() {
        assertFalse(any("{key:`setDefaults`,value:function($){a(f,$)}}"), "plain identifier value");
        assertFalse(any("return{key:`extra-${i}`,title:o.title,isFirst:!1}"), "template-literal key");
        assertFalse(any("return{key:`gallery-${o.pageId}`,title:o.title,editRoute:null}"), "interpolated key");
        assertFalse(any("{labelKey:`Colombia`,url:`https://stats.uptimerobot.com/2KwXWc5Gb2`,status:this.x}"),
                "country label under labelKey");
        assertFalse(any("case`1.2.840.10045.2.1`:return h.subjectPrivateKey=h.subjectPublicKey,{type:`ec`};"),
                "member expression assigned to a *privateKey field");
    }

    @Test
    void templateInterpolatedUrlQueryValueIsNotACredential() {
        assertFalse(any("#n(){return`https://maps.googleapis.com/maps/api/js?key="
                + "${this.e.webSettings?.googleMapsDefaultKey??``}&libraries=marker`}"),
                "query value is a ${...} interpolation, not a key");
    }

    @Test
    void genuineSecretsInTheSameBundlesAreStillReported() {
        assertTrue(any("commonSettings={authClientId:`con20app-mscon20`,authSecret:`Z1i7xWzQpqQmsWk5bx6DBkIS`}"),
                "real authSecret");
        assertTrue(any("webSettings={uptimeRobotReadOnlyApiKey:`ur1658asdffsf15f99`}"),
                "real *ApiKey");
        // Synthetic, push-protection-safe Google key shape (sequential, not a real-looking key).
        assertTrue(scan("webSettings={googleMapsDefaultKey:`AIza12345678901234567890123456789012345`}")
                .stream().anyMatch(f -> f.issueName != null && f.issueName.contains("Google API key")),
                "Google Maps API key shape");
    }
}
