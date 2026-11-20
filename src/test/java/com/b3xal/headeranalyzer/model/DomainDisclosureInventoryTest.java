package com.b3xal.headeranalyzer.model;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class DomainDisclosureInventoryTest {
    @Test
    void retainsDisclosureWhenLaterResultOverwritesSamePath() {
        DomainData domain = new DomainData("example.test");
        HeaderFinding poweredBy = new HeaderFinding(
                "X-Powered-By technology family disclosure", "X-Powered-By", "ASP.NET",
                "Technology disclosed", "X-Powered-By: ASP.NET", Severity.LOW,
                Confidence.CERTAIN, HeaderFinding.Category.INFORMATION_DISCLOSURE);

        UrlAnalysisResult first = new UrlAnalysisResult("https://example.test/", "example.test", "/",
                List.of(poweredBy), Map.of("X-Powered-By", "ASP.NET"));
        first.method = "GET";
        domain.addResult(first);

        UrlAnalysisResult later = new UrlAnalysisResult("https://example.test/", "example.test", "/",
                List.of(), Map.of());
        later.method = "GET";
        domain.addResult(later);

        assertEquals(1, domain.getUrlResults().size());
        assertEquals(List.of(poweredBy), List.copyOf(domain.getDisclosureInventory()));
        assertEquals(1, domain.getDisclosureObservationCount(poweredBy));
    }

    @Test
    void retainsMultipleValuesForSameDisclosureHeaderOnOneHost() {
        DomainData domain = new DomainData("example.test");
        HeaderFinding kestrel = disclosure("Kestrel");
        HeaderFinding iis = disclosure("Microsoft-IIS/10.0");

        domain.addResult(new UrlAnalysisResult("https://example.test/a", "example.test", "/a",
                List.of(kestrel), Map.of("Server", "Kestrel")));
        domain.addResult(new UrlAnalysisResult("https://example.test/b", "example.test", "/b",
                List.of(iis), Map.of("Server", "Microsoft-IIS/10.0")));

        assertEquals(2, domain.getDisclosureInventory().size());
    }

    private static HeaderFinding disclosure(String value) {
        return new HeaderFinding("Server technology family disclosure", "Server", value,
                "Technology disclosed", "Server: " + value, Severity.LOW,
                Confidence.CERTAIN, HeaderFinding.Category.INFORMATION_DISCLOSURE);
    }
}
