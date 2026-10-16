package com.b3xal.headeranalyzer.browser;

import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class BrowserPayloadTest {
    @Test
    void boundsUntrustedCollectionsAndValues() {
        Map<String, Object> storage = new LinkedHashMap<>();
        for (int i = 0; i < 700; i++) storage.put("key-" + i, "x".repeat(70_000));

        BrowserPayload payload = BrowserPayload.fromJson(Map.of("localStorage", storage));

        assertEquals(500, payload.localStorage.size());
        assertEquals(65_536, payload.localStorage.get("key-0").length());
    }
}
