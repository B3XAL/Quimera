package com.b3xal.headeranalyzer.browser;

import com.b3xal.headeranalyzer.config.CookiesAndAuthConfig;
import com.b3xal.headeranalyzer.model.HeaderFinding;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BrowserStorageAnalyzerTest {

    private static final CookiesAndAuthConfig CONFIG = new CookiesAndAuthConfig(
            480, true, true, true, List.of(), List.of(), true, true, true, true,
            true, true, true, true, List.of(), List.of(), true);

    @Test
    void reportsUuidUserIdInLocalStorageAsStorageNotAuth() {
        BrowserPayload payload = BrowserPayload.fromJson(Map.of(
                "localStorage", Map.of("userId", "6189784b-fc8b-cdcd-85f7-704db4ab7831")));

        List<HeaderFinding> findings = BrowserStorageAnalyzer.analyze(payload, CONFIG);

        assertEquals(1, findings.size());
        assertEquals(HeaderFinding.Category.STORAGE, findings.get(0).category);
        assertEquals(com.b3xal.headeranalyzer.model.Severity.MEDIUM, findings.get(0).severity);
        assertTrue(findings.get(0).evidence.contains("localStorage.userId"));
    }

    @Test
    void reportsNestedUuidUserIdInSessionStorage() {
        BrowserPayload payload = BrowserPayload.fromJson(Map.of(
                "sessionStorage", Map.of("profile", "{\"userId\":\"6189784b-fc8b-cdcd-85f7-704db4ab7831\"}")));

        List<HeaderFinding> findings = BrowserStorageAnalyzer.analyze(payload, CONFIG);

        assertEquals(1, findings.size());
        assertEquals(HeaderFinding.Category.STORAGE, findings.get(0).category);
        assertEquals(com.b3xal.headeranalyzer.model.Severity.LOW, findings.get(0).severity);
        assertTrue(findings.get(0).evidence.contains("sessionStorage.profile.userId"));
    }

    @Test
    void reportsUuidEvenWhenStorageKeyIsNotIdentitySpecific() {
        BrowserPayload payload = BrowserPayload.fromJson(Map.of(
                "localStorage", Map.of("componentId", "6189784b-fc8b-cdcd-85f7-704db4ab7831")));

        List<HeaderFinding> findings = BrowserStorageAnalyzer.analyze(payload, CONFIG);
        assertEquals(1, findings.size());
        assertTrue(findings.get(0).evidence.contains("stable UUID identifier"));
    }

    @Test
    void reportsValidatedCommonIdentifyingFieldsButNotArbitraryLabels() {
        BrowserPayload payload = BrowserPayload.fromJson(Map.of(
                "localStorage", Map.of(
                        "email", "jdoe@example.test",
                        "phoneNumber", "+34 612 345 678",
                        "displayName", "Jane Doe",
                        "username", "jane.doe",
                        "emailLabel", "Email address")));

        List<HeaderFinding> findings = BrowserStorageAnalyzer.analyze(payload, CONFIG);

        assertEquals(4, findings.size());
        assertTrue(findings.stream().allMatch(f -> f.category == HeaderFinding.Category.STORAGE));
    }
}
