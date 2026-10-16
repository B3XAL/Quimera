package com.b3xal.headeranalyzer.browser;

import com.b3xal.headeranalyzer.util.JsonUtil;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BrowserEvidenceTest {

    @Test
    void syntheticResponseShowsCookieAttributesAndReadableValues() {
        BrowserPayload payload = BrowserPayload.fromJson(Map.of(
                "href", "https://example.test/login",
                "browserCookies", List.of(Map.of(
                        "name", "cookieconsent_status",
                        "value", "allow",
                        "domain", ".example.test",
                        "path", "/",
                        "secure", false,
                        "httpOnly", false,
                        "sameSite", "lax"))));

        String response = JsonUtil.write(BrowserEvidence.collectedData(
                payload, "https://example.test/login"));

        assertTrue(response.contains("\"browserCookies\""));
        assertTrue(response.contains("\"name\": \"cookieconsent_status\""));
        assertTrue(response.contains("\"secure\": false"));
        assertTrue(response.contains("\"httpOnly\": false"));
        assertTrue(response.contains("\"sameSite\": \"lax\""));
        assertTrue(response.contains("\"value\": \"allow\""));
        assertTrue(response.contains("Cookie values are URL-decoded for readability"));
    }

    @Test
    void syntheticResponseShowsOnlyDecodedCookieValue() {
        BrowserPayload payload = BrowserPayload.fromJson(Map.of(
                "href", "https://example.test/login",
                "browserCookies", List.of(Map.of(
                        "name", "session",
                        "value", "%7B%22user%22%3A%22Jane%2BDoe%22%7D",
                        "domain", "example.test",
                        "path", "/",
                        "secure", true,
                        "httpOnly", true,
                        "sameSite", "lax"))));

        String response = JsonUtil.write(BrowserEvidence.collectedData(
                payload, "https://example.test/login"));

        assertTrue(response.contains("\"value\": \"{\\\"user\\\":\\\"Jane+Doe\\\"}\""));
        assertFalse(response.contains("rawValue"));
        assertFalse(response.contains("%7B%22user%22%3A%22Jane%2BDoe%22%7D"));
        assertEquals("{\"user\":\"Jane+Doe\"}",
                BrowserEvidence.decodeCookieValue("%257B%2522user%2522%253A%2522Jane%252BDoe%2522%257D"));
        assertEquals("literal+plus", BrowserEvidence.decodeCookieValue("literal+plus"));
        assertEquals("bad%ZZvalue", BrowserEvidence.decodeCookieValue("bad%ZZvalue"));
    }
}
