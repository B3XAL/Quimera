package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.config.QuimeraSettings;
import com.b3xal.headeranalyzer.model.UrlAnalysisResult;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HeaderPresencePolicyTest {

    private final HeaderAnalysisEngine engine =
            new HeaderAnalysisEngine(new RuleStore(null), new QuimeraSettings());

    @Test
    void absenceOnlyReportsHeadersThatRemainIntentionalFindings() {
        UrlAnalysisResult result = engine.analyze("https://example.test/account",
                Map.of("Content-Type", "text/html"), 200, "<html></html>", "GET");

        assertTrue(has(result, "Missing Content Security Policy"));
        assertTrue(has(result, "Missing HTTP Strict Transport Security"));
        assertTrue(has(result, "Missing Clickjacking Protection"));
        assertFalse(has(result, "Missing Referrer Policy"));
        assertFalse(has(result, "Missing Permissions Policy"));
        assertFalse(has(result, "Missing Cross-Origin Opener Policy"));
        assertFalse(has(result, "HSTS does not cover subdomains"));
    }

    @Test
    void deepCspAnalysisStillRunsWhileMissingCspRemainsEnabled() {
        UrlAnalysisResult result = engine.analyze("https://example.test/account",
                Map.of("Content-Type", "text/html",
                        "Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'"),
                200, "<html></html>", "GET");

        assertFalse(has(result, "Missing Content Security Policy"));
        assertTrue(result.findings.stream().anyMatch(f -> f.issueName.startsWith("CSP:")));
    }

    @Test
    void validXfoSuppressesDuplicateMissingFrameAncestorsFinding() {
        UrlAnalysisResult result = engine.analyze("https://example.test/account",
                Map.of("Content-Type", "text/html", "X-Frame-Options", "DENY",
                        "Content-Security-Policy", "default-src 'self'"),
                200, "<html></html>", "GET");

        assertFalse(has(result, "Missing Clickjacking Protection"));
        assertFalse(has(result, "CSP: frame-ancestors directive missing"));
    }

    private static boolean has(UrlAnalysisResult result, String issueName) {
        return result.findings.stream().anyMatch(f -> issueName.equals(f.issueName));
    }
    @Test
    void approvedDocumentAndTransportBoundaries() {
        for (String method : java.util.List.of("HEAD", "OPTIONS", "TRACE")) {
            var r = engine.analyze("https://example.test/login", Map.of("Content-Type","text/html"),
                    200, "<form><input type=password></form>", method);
            assertFalse(has(r,"Missing Clickjacking Protection"), method);
        }
        for (int status : new int[]{101,204,205,304}) {
            var r = engine.analyze("https://example.test/login", Map.of("Content-Type","text/html"),
                    status, "<form></form>", "GET");
            assertFalse(has(r,"Missing Clickjacking Protection"), Integer.toString(status));
        }
        for (int status : new int[]{400,401,403,404,405,500,503}) {
            var error = engine.analyze("https://example.test/login", Map.of("Content-Type","text/html"),
                    status, "<form><input type=password></form>", "GET");
            assertFalse(has(error,"Missing Clickjacking Protection"), Integer.toString(status));
            assertFalse(has(error,"Missing HTTP Strict Transport Security"), Integer.toString(status));
        }
        for (int status : new int[]{301,302,303,307,308}) {
            var redirect = engine.analyze("https://example.test/login", Map.of("Location", "/signin"),
                    status, "", "GET");
            var missingHsts = redirect.findings.stream()
                    .filter(f -> f.issueName.equals("Missing HTTP Strict Transport Security")).findFirst();
            assertTrue(missingHsts.isPresent(), Integer.toString(status));
            assertTrue(missingHsts.get().severity
                    == com.b3xal.headeranalyzer.model.Severity.INFORMATION, Integer.toString(status));
        }
        var http = engine.analyze("http://example.test/", Map.of("Strict-Transport-Security","max-age=0"),204,"","HEAD");
        assertFalse(http.findings.stream().anyMatch(f->f.headerName.equalsIgnoreCase("Strict-Transport-Security")));
        var https = engine.analyze("https://example.test/", Map.of("Strict-Transport-Security","max-age=0"),500,"","HEAD");
        assertFalse(has(https,"HSTS policy explicitly disabled (max-age=0)"));
    }

    @Test
    void approvedPolicyParsingAndOverlap() {
        assertTrue(HeaderReportContext.protectiveXfo("DENY, DENY"));
        assertTrue(HeaderReportContext.protectiveXfo("ALLOWALL, INVALID"));
        assertFalse(HeaderReportContext.protectiveXfo("\"INVALID,DENY,INVALID\""));
        assertTrue(HeaderReportContext.protectiveXfo("SAMEORIGIN\nDENY"));
        assertFalse(HeaderReportContext.protectiveXfo("ALLOW-FROM https://example.test"));
        assertTrue(HeaderReportContext.restrictiveFrameAncestors("frame-ancestors *; frame-ancestors 'none', frame-ancestors 'self'", "https://example.test/"));
        assertFalse(HeaderReportContext.restrictiveFrameAncestors("frame-ancestors *; frame-ancestors 'none'", "https://example.test/"));
        var protectedResult=engine.analyze("https://example.test/", Map.of("Content-Type","text/html",
                "X-Frame-Options","ALLOW-FROM https://bad.test", "Content-Security-Policy","frame-ancestors 'none'"),200,"<form></form>","GET");
        assertFalse(protectedResult.findings.stream().anyMatch(f->f.headerName.equalsIgnoreCase("X-Frame-Options")));
        assertTrue(HeaderReportContext.hsts("max-age=100; MAX-AGE=100").issueName.equals("Invalid HSTS policy"));
        org.junit.jupiter.api.Assertions.assertNull(HeaderReportContext.hsts("max-age=31536000\nmax-age=0"));
        var reportOnly=engine.analyze("https://example.test/", Map.of("Content-Type","text/html",
                "Content-Security-Policy-Report-Only","script-src * 'unsafe-inline'"),200,"<html></html>","GET");
        assertFalse(reportOnly.findings.stream().anyMatch(f->f.issueName.startsWith("CSP:")));
    }

    @Test
    void approvedCacheContextDoesNotTreatAuthenticationAsPrivateContent() {
        var publicLogin=engine.analyze("https://example.test/login",Map.of("Content-Type","text/html","Cache-Control","public"),
                Map.of("Authorization","Bearer example"),200,"<form><input type=password></form>","GET");
        assertFalse(publicLogin.findings.stream().anyMatch(f->f.headerName.equalsIgnoreCase("Cache-Control")));
        var privateAsset=engine.analyzeResponseHeaders("https://example.test/invoice.css",Map.of("Content-Type","text/css","Cache-Control","public, max-age=600"),
                Map.of(),200,"{\"access_token\":\"private-user-token\"}","GET");
        assertTrue(privateAsset.findings.stream().anyMatch(f->f.headerName.equalsIgnoreCase("Cache-Control")));
        var probe=engine.analyzeResponseHeaders("https://example.test/invoice.css",Map.of("Content-Type","text/css","Cache-Control","public"),
                Map.of("X-Quimera-Internal-Probe","1"),200,"{\"access_token\":\"private-user-token\"}","GET");
        assertFalse(probe.findings.stream().anyMatch(f->f.headerName.equalsIgnoreCase("Cache-Control")));
        assertFalse(CachePolicy.parse(Map.of("Cache-Control","public, private")).sharedReuseAllowed(Map.of()));
        assertTrue(CachePolicy.parse(Map.of("Cache-Control","public, private=\"Set-Cookie, X-User\", max-age=600")).sharedReuseAllowed(Map.of()));
        assertFalse(CachePolicy.parse(Map.of("Cache-Control","public, no-cache")).sharedReuseAllowed(Map.of()));
    }

    @Test
    void approvedMimeAndHttpIdentityChecks() {
        var valid=engine.analyze("https://example.test/a.js",Map.of("Content-Type","text/plain","X-Content-Type-Options","nosniff, other"),
                Map.of("Sec-Fetch-Dest","script"),200,"alert(1)","GET");
        assertFalse(valid.findings.stream().anyMatch(f->f.headerName.equalsIgnoreCase("X-Content-Type-Options")));
        var invalid=engine.analyze("https://example.test/a.js",Map.of("Content-Type","text/plain","X-Content-Type-Options","not-nosniff"),
                Map.of("Sec-Fetch-Dest","script"),200,"alert(1)","GET");
        assertTrue(invalid.findings.stream().anyMatch(f->f.headerName.equalsIgnoreCase("X-Content-Type-Options")));
        assertFalse(ActiveHeaderScanner.sameApplicationContent(204,"",Map.of(),204,"",Map.of()));
        assertFalse(ActiveHeaderScanner.sameApplicationContent(200,"<title>Service unavailable</title>",Map.of(),200,"<title>Service unavailable</title>",Map.of()));
        assertTrue(ActiveHeaderScanner.sameApplicationContent(200,"<form action='https://example.test/login'></form>",Map.of(),200,"<form action='http://example.test/login'></form>",Map.of()));
    }

    @Test
    void plaintextProbeRejectsImplicitlyFollowedHttpsRedirects() {
        assertTrue(ActiveHeaderScanner.isExpectedProbeResponseUrl(
                "http://example.test/versions.json", "http://example.test/versions.json"));
        assertTrue(ActiveHeaderScanner.isExpectedProbeResponseUrl(
                "http://example.test/versions.json", "http://example.test:80/versions.json"));
        assertFalse(ActiveHeaderScanner.isExpectedProbeResponseUrl(
                "http://example.test/versions.json", "https://example.test/versions.json"));
        assertFalse(ActiveHeaderScanner.isExpectedProbeResponseUrl(
                "http://example.test/versions.json", "http://example.test/other.json"));
    }

    @Test
    void selectedInventoriesAndReferrerDoNotRaiseLoginSeverity() {
        var r=engine.analyze("https://example.test/login",Map.of("Content-Type","text/html","Server","edge03",
                "Referrer-Policy","unsafe-url","X-Envoy-Upstream-Service-Time","1000","X-Version","2026-09-09"),
                200,"<form><input type=password></form>","GET");
        assertFalse(r.findings.stream().anyMatch(f->f.headerName.equalsIgnoreCase("Referrer-Policy")
                &&f.severity==com.b3xal.headeranalyzer.model.Severity.HIGH));
        assertFalse(r.findings.stream().anyMatch(f->java.util.Set.of("Server","X-Version","X-Envoy-Upstream-Service-Time")
                .contains(f.headerName)&&f.severity!=com.b3xal.headeranalyzer.model.Severity.INFORMATION));
        var css=engine.analyze("https://example.test/style.css",Map.of("Content-Type","text/css","Referrer-Policy","unsafe-url"),
                200,"body{background:url(https://other.test/x)}","GET");
        assertTrue(css.findings.stream().anyMatch(f->f.headerName.equalsIgnoreCase("Referrer-Policy")));
        var redirected=engine.analyze("https://example.test/x",Map.of("Location","https://other.test/","Referrer-Policy","unsafe-url"),
                302,"","GET");
        assertTrue(redirected.findings.stream().anyMatch(f->f.headerName.equalsIgnoreCase("Referrer-Policy")));
        org.junit.jupiter.api.Assertions.assertNull(HeaderReportContext.sourcePath("nonsense"));
        org.junit.jupiter.api.Assertions.assertEquals("C:\\site\\index.cs",HeaderReportContext.sourcePath(
                java.util.Base64.getEncoder().encodeToString("C:\\site\\index.cs".getBytes(java.nio.charset.StandardCharsets.UTF_8))));
    }

    @Test
    void knownCatoServerIdentitiesNeverCreateBuiltInDisclosureFindings() {
        for (String value : java.util.List.of("Cato", "Cato Networks", " cAtO ")) {
            var result = engine.analyze("https://example.test/", Map.of(
                    "Content-Type", "text/html", "Server", value), 200, "<html></html>", "GET");
            assertFalse(result.findings.stream().anyMatch(f -> f.headerName.equalsIgnoreCase("Server")), value);
        }
    }

    @Test
    void blankServerHeaderNeverCreatesAnInformationDisclosureFinding() {
        for (String value : java.util.List.of("", "   ", "\t")) {
            var result = engine.analyze("https://example.test/", Map.of(
                    "Content-Type", "text/html", "Server", value), 200, "<html></html>", "GET");
            assertFalse(result.findings.stream().anyMatch(f -> f.headerName.equalsIgnoreCase("Server")),
                    "Blank Server value must not disclose a technology: '" + value + "'");
        }
    }

}
