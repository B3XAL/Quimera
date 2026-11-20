package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.config.CookiesAndAuthConfig;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class WebStorageAnalyzerTest {

    @Test
    void preservesLiteralDoubleQuotedSetItemCallForResponseSearch() {
        String call = "sessionStorage.setItem(\"access_token\",t.payload.response.access_token)";

        var findings = WebStorageAnalyzer.analyze("before;" + call + ";after", null, config());
        var finding = findings.stream()
                .filter(f -> f.issueName.startsWith("Sensitive-looking key stored via Web Storage"))
                .findFirst().orElseThrow();

        assertEquals("(Web Storage)", finding.headerName);
        assertEquals(call, finding.headerValue);
    }

    @Test
    void preservesLiteralSingleQuotesAndSpacingToo() {
        String call = "localStorage . setItem ( 'refresh_token' , response.refresh_token )";

        var findings = WebStorageAnalyzer.analyze(call, null, config());
        var finding = findings.stream()
                .filter(f -> f.issueName.startsWith("Sensitive-looking key stored via Web Storage"))
                .findFirst().orElseThrow();

        assertEquals(call, finding.headerValue);
    }

    private static CookiesAndAuthConfig config() {
        return new CookiesAndAuthConfig(60, true, true, true, List.of(), List.of(),
                true, true, true, true, true, true, true, true,
                List.of(), List.of(), true);
    }
}
