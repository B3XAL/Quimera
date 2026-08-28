package com.b3xal.headeranalyzer.util;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class JsonUtilTest {
    @Test
    void roundTripsStructuredData() {
        Map<String, Object> source = Map.of("name", "Quimera", "enabled", true,
                "values", List.of(1, "two", false));
        Object parsed = JsonUtil.parse(JsonUtil.write(source));
        assertInstanceOf(Map.class, parsed);
        assertEquals("Quimera", ((Map<?, ?>) parsed).get("name"));
    }

    @Test
    void rejectsTrailingGarbage() {
        assertThrows(IllegalArgumentException.class, () -> JsonUtil.parse("{\"ok\":true} garbage"));
    }
}
