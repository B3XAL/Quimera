package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.model.HeaderFinding;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Covers credentials carried in the query string of URLs embedded in the body, plus the second
 * batch of distinctive-prefix provider signatures. Signature fixtures use all-A/all-zero bodies on
 * purpose: they match the format but carry no entropy, so a secret scanner will not treat the test
 * as a live key.
 */
class CredentialUrlQueryAndSignatureTest {
    private static final String SECRET = "Z1i7xWzQpqQmsWk5bx6DBkIS";

    private static boolean issue(List<HeaderFinding> f, String needle) {
        return f.stream().anyMatch(x -> x.issueName != null && x.issueName.contains(needle));
    }
    private static List<HeaderFinding> scan(String body) {
        return CredentialBodyAnalyzer.analyze(body, "text/javascript", "response", null);
    }

    @Test
    void detectsSecretsInUrlQueryParameters() {
        assertFalse(scan("img='https://cdn.example.test/a?access_token=" + SECRET + "&w=20'")
                .isEmpty(), "access_token in URL query");
        assertFalse(scan("u='https://x.example.test/d?token=" + SECRET + "%3D%3D'")
                .isEmpty(), "url-encoded token value");
    }

    @Test
    void doesNotFlagOrdinaryQueryParameters() {
        assertTrue(scan("'https://api.example.test/v1?page=2&sort=name&q=searchtermlong'").isEmpty(),
                "non-sensitive params");
        assertTrue(scan("'https://x.example.test/j?callback=jsonpHandlerFunctionName'").isEmpty(),
                "jsonp callback is not a credential");
        assertTrue(scan("'https://x.example.test?token=abc123'").isEmpty(),
                "short low-entropy token value");
    }

    @Test
    void detectsSecondBatchProviderSignatures() {
        // Patterned-but-synthetic values: they satisfy each format yet have no long single-char run
        // (so the placeholder filter does not drop them) and are plainly not real keys.
        String b = "aB3kd9Qz";       // 8-char mixed block, distinct chars, no repeats
        String hex = "0a1b2c3d";     // 8-char hex block
        assertTrue(issue(scan("x={t:'hvs." + b.repeat(3) + "'}"), "HashiCorp Vault token"));
        assertTrue(issue(scan("x='dp.st.prd." + b.repeat(5) + "'"), "Doppler token"));
        assertTrue(issue(scan("x='glsa_" + b.repeat(4) + "_" + hex + "'"),
                "Grafana service account/cloud token"));
        assertTrue(issue(scan("x='dapi" + hex.repeat(4) + "'"), "Databricks personal access token"));
        assertTrue(issue(scan("x='ATATT3xFfGF0" + b.repeat(24) + "'"), "Atlassian API token"));
        assertTrue(issue(scan("x='hf_" + b.repeat(4) + "'"), "Hugging Face user access token"));
        assertTrue(issue(scan("x='sbp_" + hex.repeat(5) + "'"), "Supabase token"));
        assertTrue(issue(scan("x='sb_secret_" + b.repeat(3) + "'"), "Supabase token"));
        assertTrue(issue(scan("x='dt0c01." + b.repeat(3) + "." + b.repeat(8) + "'"), "Dynatrace API token"));
    }

    @Test
    void ordinaryTokensNearThosePrefixesDoNotFalsePositive() {
        // Similar-looking but wrong shapes must not match.
        assertFalse(issue(scan("var hvac='heating system controller';"), "Vault"));
        assertFalse(issue(scan("var label='dapibus ante ipsum';"), "Databricks"));
        assertFalse(issue(scan("var s='glsa_tooShort';"), "Grafana"));
        assertFalse(issue(scan("var greeting='hf_ is the prefix we use';"), "Hugging Face"));
        assertFalse(issue(scan("var x='sb_secret_x';"), "Supabase"));          // too short
        assertFalse(issue(scan("var note='dt0c01 is a token kind';"), "Dynatrace")); // no dotted body
    }
}
