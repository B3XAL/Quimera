package com.b3xal.headeranalyzer.analyzer;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class CookieEmbeddedPasswordTokenTest {
    private static final String TOKEN = "59c2fa6c65cf4112970b230da09d5f65";

    @Test
    void reportsPasswordConfirmationTicketInsideReturnUrlCookie() {
        var findings = AuthHeaderAnalyzer.analyzeSensitiveUrlInCookie("returnUrl",
                "/confirm-password?userid=6a969ed5983d9c1c78126ce9" +
                        "&ticketid=6a969fc5983d9c1c78126cf8&ticket=" + TOKEN);

        assertEquals(1, findings.size());
        assertEquals(TOKEN, findings.get(0).headerValue);
        assertTrue(findings.get(0).evidence.contains("query parameter ticket=" + TOKEN));
        assertFalse(findings.get(0).evidence.contains("ticketid="));
        assertFalse(findings.get(0).evidence.contains("userid="));
    }

    @Test
    void handlesUrlEncodedCookieValue() {
        var findings = AuthHeaderAnalyzer.analyzeSensitiveUrlInCookie("returnUrl",
                "%2Fconfirm-password%3Fticket%3D" + TOKEN);
        assertEquals(1, findings.size());
    }

    @Test
    void preservesSetCookieAsTheDetectionSource() {
        var findings = AuthHeaderAnalyzer.analyzeSensitiveUrlInCookie("returnUrl",
                "/confirm-password?ticket=" + TOKEN, "Set-Cookie");
        assertEquals("Set-Cookie", findings.get(0).headerName);
        assertTrue(findings.get(0).evidence.startsWith("Set-Cookie: returnUrl"));
    }

    @Test
    void ignoresIdentifiersAndUnrelatedTicketParameters() {
        assertTrue(AuthHeaderAnalyzer.analyzeSensitiveUrlInCookie("returnUrl",
                "/confirm-password?userid=abc123456789012345&ticketid=abc123456789012345").isEmpty());
        assertTrue(AuthHeaderAnalyzer.analyzeSensitiveUrlInCookie("preferences",
                "/events?ticket=" + TOKEN).isEmpty());
    }

    @Test
    void ignoresTrackingCookies() {
        assertTrue(AuthHeaderAnalyzer.analyzeSensitiveUrlInCookie("_ga",
                "GA1.2.2077466867.1773761059").isEmpty());
        assertTrue(AuthHeaderAnalyzer.analyzeSensitiveUrlInCookie("_gid",
                "GA1.2.395920896.1788166281").isEmpty());
    }
}
