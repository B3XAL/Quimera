package com.b3xal.headeranalyzer.analyzer;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.jupiter.api.Test;

class CookieEncodingAnalyzerTest {
    @Test void finds_only_decodable_structured_transport_data() {
        String json = "{\"user_id\":\"19bfb2f7\",\"access_token\":\"secret-value\"}";
        String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8));
        assertEquals(1, CookieEncodingAnalyzer.analyze("didomi_token", encoded, "Cookie").size());
        assertEquals(1, CookieEncodingAnalyzer.analyze("prefs", "%7B%22access_token%22%3A%22secret%22%7D", "Set-Cookie").size());
        assertTrue(CookieEncodingAnalyzer.analyze("didomi_token", Base64.getEncoder().encodeToString(
                "{\"user_id\":\"19bfb2f7\",\"vendors\":[\"google\"]}".getBytes(StandardCharsets.UTF_8)), "Cookie").isEmpty());
        assertTrue(CookieEncodingAnalyzer.analyze("sid", "mE1wqp0xE3jvQ_2oJm9C8w", "Cookie").isEmpty());
    }
}
