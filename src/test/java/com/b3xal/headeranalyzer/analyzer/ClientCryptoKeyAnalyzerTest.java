package com.b3xal.headeranalyzer.analyzer;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ClientCryptoKeyAnalyzerTest {

    @Test
    void detectsOnlyLiteralKeyMaterialUsedByKnownSymmetricApis() {
        String script = "const cryptKey = 'validated-key-material';\n"
                + "CryptoJS.AES.encrypt(message, cryptKey);\n"
                + "createCipheriv('aes-256-gcm', 'another-real-key-value', nonce);\n"
                + "sjcl.encrypt('third-real-key-value', message);";

        var findings = ClientCryptoKeyAnalyzer.analyze(script, "application/javascript", "https://example.test/app.js");

        assertEquals(3, findings.size());
        assertTrue(findings.stream().anyMatch(f -> f.headerValue.equals("validated-key-material")));
        assertTrue(findings.stream().allMatch(f -> f.evidence.contains("Client key material:")));
    }

    @Test
    void ignoresPlaceholdersUnrelatedStringsAndBinaryResponses() {
        String script = "const iv = 'initial-vector-value';\n"
                + "const key = 'replace-with-your-key';\n"
                + "CryptoJS.AES.encrypt(message, key);\n"
                + "const text = 'validated-key-material';";

        assertTrue(ClientCryptoKeyAnalyzer.analyze(script, "application/javascript", "https://example.test/app.js").isEmpty());
        assertTrue(ClientCryptoKeyAnalyzer.analyze("CryptoJS.AES.encrypt(a, 'real-key-material')",
                "image/jpeg", "https://example.test/image.jpg").isEmpty());
    }
}
