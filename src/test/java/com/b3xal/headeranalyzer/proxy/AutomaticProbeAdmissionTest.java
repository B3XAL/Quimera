package com.b3xal.headeranalyzer.proxy;

import burp.api.montoya.core.ToolType;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

class AutomaticProbeAdmissionTest {
    @Test void admitsOnly_safe_dynamic_get_or_head_responses() {
        assertTrue(QuimeraHttpHandler.isAutomaticProbeCandidate("https://app.example.test/api/profile", "GET", (short) 200, "application/json"));
        assertTrue(QuimeraHttpHandler.isAutomaticProbeCandidate("https://app.example.test/account", "HEAD", (short) 302, "text/html"));
        assertFalse(QuimeraHttpHandler.isAutomaticProbeCandidate("https://app.example.test/form", "POST", (short) 200, "text/html"));
        assertFalse(QuimeraHttpHandler.isAutomaticProbeCandidate("https://app.example.test/site.css?v=1", "GET", (short) 200, "text/css"));
        assertFalse(QuimeraHttpHandler.isAutomaticProbeCandidate("https://app.example.test/collect", "GET", (short) 204, "application/javascript"));
    }

    @Test void never_amplifies_scanner_or_extension_traffic() {
        assertTrue(QuimeraHttpHandler.isAutomaticProbeSource(ToolType.PROXY));
        assertTrue(QuimeraHttpHandler.isAutomaticProbeSource(ToolType.TARGET));
        assertFalse(QuimeraHttpHandler.isAutomaticProbeSource(ToolType.SCANNER));
        assertFalse(QuimeraHttpHandler.isAutomaticProbeSource(ToolType.EXTENSIONS));
    }
}
