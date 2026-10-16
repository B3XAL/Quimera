package com.b3xal.headeranalyzer.analyzer;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TraceProbeDetectionTest {
    private static final String MARKER = "2d326d67-82d4-4db9-8dd3-9baa61c6688f";

    @Test
    void acceptsOnlyRealTraceEchoWithControlledMarker() {
        String body = "TRACE /account HTTP/1.1\r\nHost: example.test\r\n" +
                "X-Quimera-Trace-Probe: " + MARKER + "\r\n\r\n";
        assertTrue(ActiveHeaderScanner.isGenuineTraceEcho(body, MARKER));
    }

    @Test
    void rejectsNormalPageEvenWhenTraceReturnedHttp200() {
        assertFalse(ActiveHeaderScanner.isGenuineTraceEcho(
                "<!doctype html><title>Home</title><p>Normal application response</p>", MARKER));
    }

    @Test
    void rejectsCoincidentalTraceTextWithoutUniqueHeaderEcho() {
        assertFalse(ActiveHeaderScanner.isGenuineTraceEcho(
                "TRACE / HTTP/1.1\r\nHost: example.test\r\n", MARKER));
    }

    @Test
    void rejectsMarkerReflectionWithoutTraceRequestLine() {
        assertFalse(ActiveHeaderScanner.isGenuineTraceEcho(
                "X-Quimera-Trace-Probe: " + MARKER, MARKER));
    }
}
