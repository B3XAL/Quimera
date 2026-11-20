package com.b3xal.headeranalyzer.model;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Mirrors DomainDisclosureInventoryTest for the equivalent COOKIE-category bug: the Report's
 * COOKIES section used to read only the currently-selected row's own findings, so a cookie set on
 * a DIFFERENT URL of the same host (a login/auth endpoint, not whichever page happens to be
 * selected in the Logger) never showed up, the same "not aggregated across the host" bug already
 * fixed for the disclosure section. */
class DomainCookieInventoryTest {

    @Test
    void retainsCookieFindingWhenLaterResultOverwritesSamePath() {
        DomainData domain = new DomainData("example.test");
        HeaderFinding missingSecure = cookieFinding("Cookie missing Secure flag: session_id");

        UrlAnalysisResult first = new UrlAnalysisResult("https://example.test/login", "example.test", "/login",
                List.of(missingSecure), Map.of("Set-Cookie", "session_id=abc"));
        first.method = "POST";
        domain.addResult(first);

        UrlAnalysisResult later = new UrlAnalysisResult("https://example.test/login", "example.test", "/login",
                List.of(), Map.of());
        later.method = "POST";
        domain.addResult(later);

        assertEquals(1, domain.getUrlResults().size());
        assertEquals(List.of(missingSecure), List.copyOf(domain.getCookieInventory()));
        assertEquals(1, domain.getCookieObservationCount(missingSecure));
    }

    /** The exact real-world shape the user hit: the cookie is set on ONE url (a login request),
     * a completely different, cookie-less URL on the same host is "currently selected" for the
     * report. The cookie finding must still be part of the host's aggregate. */
    @Test
    void cookieSetOnADifferentUrlOfTheSameHostStillAppearsInTheHostAggregate() {
        DomainData domain = new DomainData("example.test");
        HeaderFinding missingHttpOnly = cookieFinding("Cookie missing HttpOnly flag: session_id");

        domain.addResult(new UrlAnalysisResult("https://example.test/login", "example.test", "/login",
                List.of(missingHttpOnly), Map.of("Set-Cookie", "session_id=abc")));
        // A plain page with no cookie findings at all, the row an analyst might have selected.
        domain.addResult(new UrlAnalysisResult("https://example.test/about", "example.test", "/about",
                List.of(), Map.of("Content-Type", "text/html")));

        long cookieFindingsAcrossHost = domain.getUrlResults().values().stream()
                .flatMap(r -> r.findings.stream())
                .filter(f -> f.category == HeaderFinding.Category.COOKIE)
                .count();
        assertEquals(1, cookieFindingsAcrossHost);
        assertTrue(domain.getCookieInventory().stream().anyMatch(f -> f.equals(missingHttpOnly)));
    }

    @Test
    void distinguishesTwoDifferentCookiesWithTheSameIssueByNameEmbeddedInIssueName() {
        DomainData domain = new DomainData("example.test");
        HeaderFinding sessionCookie = cookieFinding("Cookie missing Secure flag: session_id");
        HeaderFinding csrfCookie = cookieFinding("Cookie missing Secure flag: csrf_token");

        domain.addResult(new UrlAnalysisResult("https://example.test/login", "example.test", "/login",
                List.of(sessionCookie, csrfCookie), Map.of()));

        assertEquals(2, domain.getCookieInventory().size());
    }

    private static HeaderFinding cookieFinding(String issueName) {
        return new HeaderFinding(issueName, "Set-Cookie", "session_id=abc",
                "Cookie flag issue", "Set-Cookie: session_id=abc", Severity.MEDIUM,
                Confidence.CERTAIN, HeaderFinding.Category.COOKIE);
    }
}
