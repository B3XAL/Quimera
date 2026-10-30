package com.b3xal.headeranalyzer.ui;

import com.b3xal.headeranalyzer.model.Confidence;
import com.b3xal.headeranalyzer.model.HeaderFinding;
import com.b3xal.headeranalyzer.model.Severity;
import com.b3xal.headeranalyzer.model.UrlAnalysisResult;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CookiePanelAuthSelectionTest {

    @Test
    void resolvesJwtPiiGroupRepresentativeToActualAuthorizationFinding() {
        HeaderFinding actual = finding("Authorization", "jwt-current");
        HeaderFinding subjectGroupedRepresentative = finding("(JWT personal data)", "subject-fingerprint");
        UrlAnalysisResult result = new UrlAnalysisResult("https://example.test/api", "example.test", "/api",
                List.of(actual), Map.of());

        HeaderFinding resolved = CookiePanel.matchingAuthFinding(result, subjectGroupedRepresentative);

        assertEquals("Authorization", resolved.headerName);
        assertEquals("jwt-current", resolved.headerValue);
    }

    private static HeaderFinding finding(String headerName, String headerValue) {
        return new HeaderFinding("Personal data exposed in readable JWT claims", headerName, headerValue,
                "test", "test", Severity.LOW, Confidence.FIRM, HeaderFinding.Category.AUTH);
    }
}
