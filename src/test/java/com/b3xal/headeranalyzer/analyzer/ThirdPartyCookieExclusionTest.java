package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.config.QuimeraSettings;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ThirdPartyCookieExclusionTest {
    private final QuimeraSettings settings = new QuimeraSettings();

    @Test
    void microsoftOauthProviderCookieIsExcludedFromPassiveCookieAuditsByDefault() {
        var config = settings.cookiesAndAuthConfig();
        for (String name : new String[]{"oauth2_microsoft", "oauth2_microsoft_silent:ab1e0f6c-9025-43a3-8760-436651807dc3",
                "oauth2_microsoft:452975fb-5770-43b7-9d1b-586028d6b9a8"}) {
            assertTrue(CookieAnalyzer.isKnownTrackingCookie(name, config), name);
            assertFalse(CookieAnalyzer.nameLooksSensitive(name, config), name);
            assertTrue(CookieAnalyzer.analyze(name + "=opaque; Path=/; HttpOnly; Max-Age=31536000",
                    "example.test", config).isEmpty(), name);
            assertTrue(AuthHeaderAnalyzer.analyzeCookieHeaderAuth(name + "=opaque", config).isEmpty(), name);
        }
    }

    @Test
    void darkReaderCookieVariantsAreAlwaysExcludedEvenWhenTrackingExclusionsAreDisabled() {
        settings.setCookieTrackingSkipEnabled(false);
        var config = settings.cookiesAndAuthConfig();
        for (String name : new String[]{"__darkreader__", "__DarkReader__", "darkreader", "prefix_darkreader_state",
                "server-telemetry-6d298719-2396-44d6-9d89-21ebfc6ebe4c"}) {
            assertTrue(CookieAnalyzer.isExcludedCookie(name), name);
            assertFalse(CookieAnalyzer.nameLooksSensitive(name, config), name);
            assertTrue(CookieAnalyzer.analyze(name + "=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.signature; Path=/",
                    "example.test", config).isEmpty(), name);
            assertTrue(AuthHeaderAnalyzer.analyzeCookieHeaderAuth(name
                    + "=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.signature", config).isEmpty(), name);
        }
    }

    @Test
    void persistentCsrfCookieIsNotMisclassifiedAsALongLivedSession() {
        var config = settings.cookiesAndAuthConfig();
        var csrfFindings = CookieAnalyzer.analyze(
                "csrftoken=value; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=31449600",
                "example.test", config);
        assertFalse(csrfFindings.stream().anyMatch(f ->
                f.issueName.startsWith("Session cookie has a long lifetime")), csrfFindings.toString());

        var sessionFindings = CookieAnalyzer.analyze(
                "sessionid=value; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=31449600",
                "example.test", config);
        assertTrue(sessionFindings.stream().anyMatch(f ->
                f.issueName.startsWith("Session cookie has a long lifetime")), sessionFindings.toString());
    }
}
