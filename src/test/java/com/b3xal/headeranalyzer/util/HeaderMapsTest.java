package com.b3xal.headeranalyzer.util;

import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class HeaderMapsTest {
    @Test
    void preservesRepeatedResponseHeaders() {
        Map<String, String> headers = new LinkedHashMap<>();
        HeaderMaps.addResponse(headers, "Set-Cookie", "a=1");
        HeaderMaps.addResponse(headers, "Set-Cookie", "b=2");
        assertEquals("a=1\nb=2", headers.get("Set-Cookie"));
    }
}
