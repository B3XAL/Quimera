package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.config.QuimeraSettings;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class F5InfrastructureCookieTest {
    private static final String NAME = "f5avraaaaaaaaaaaaaaaa_session_";
    private static final String VALUE =
            "JCHAJMBIOEOANDMODGCIBLEFEBKINDEBDIGDIBNCBGDFPGFNNBBMJABDLLADKEEBMGKDMPGLJCMKHLJBGKEAIOBNAOMIHEGKAEOJFMLHCOMBFBILMBIFBKIMGIPBNEOM";

    @Test
    void excludesF5AsmCookieFromApplicationCookieFindings() {
        var config = new QuimeraSettings().cookiesAndAuthConfig();
        assertTrue(CookieAnalyzer.analyze(NAME + "=" + VALUE + "; Path=/", "example.test", config)
                .isEmpty());
        assertTrue(AuthHeaderAnalyzer.analyzeCookieHeaderAuth(NAME + "=" + VALUE, config).isEmpty());
        assertTrue(CookieAnalyzer.isInfrastructureCookie(NAME));
        assertTrue(!CookieAnalyzer.nameLooksSensitive(NAME, config));
    }

    @Test
    void fingerprintsF5AdvancedWafFromItsCookie() {
        var technologies = TechFingerprinter.analyze(Map.of(
                "Set-Cookie", NAME + "=" + VALUE + "; Path=/; Secure; HttpOnly"));

        assertEquals(1, technologies.size());
        assertEquals("F5 BIG-IP Advanced WAF (ASM)", technologies.get(0).product);
        assertEquals(NAME, technologies.get(0).rawValue);
    }

    @Test
    void fingerprintsF5AdvancedWafFromRequestCookieWhenSetCookieWasNotCaptured() {
        var technologies = TechFingerprinter.analyzeRequest(Map.of(
                "Cookie", "ordinary=value; " + NAME + "=" + VALUE + "; another=value"));

        assertEquals(1, technologies.size());
        assertEquals("F5 BIG-IP Advanced WAF (ASM)", technologies.get(0).product);
        assertEquals("Cookie", technologies.get(0).sourceHeader);
    }
}
