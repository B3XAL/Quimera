package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.config.QuimeraSettings;
import com.b3xal.headeranalyzer.model.*;
import org.junit.jupiter.api.Test;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class HeaderReviewRegressionTest {

    @Test
    void reportsActiveXssProtectionOnlyForHtmlDocuments() {
        assertTrue(has(analyze(Map.of("Content-Type", "text/html", "X-XSS-Protection", "1; mode=block"),
                Map.of(), "<html><body>page</body></html>", "GET"), "X-XSS-Protection"));
        assertFalse(has(analyze(Map.of("Content-Type", "application/json", "X-XSS-Protection", "1; mode=block"),
                Map.of(), "{\"ok\":true}", "GET"), "X-XSS-Protection"));
    }
    final RuleStore rules = new RuleStore(null);
    final HeaderAnalysisEngine engine = new HeaderAnalysisEngine(rules,new QuimeraSettings());
    UrlAnalysisResult analyze(Map<String,String> response, Map<String,String> request,String body,String method) {
        return engine.analyze("https://example.test/a",response,request,200,body,method);
    }
    boolean has(UrlAnalysisResult r,String header) {return r.findings.stream().anyMatch(f->f.headerName.equalsIgnoreCase(header));}
    @Test void allFramingFindingsDisappearOnHead() {
        var r=analyze(Map.of("Content-Type","text/html","Content-Security-Policy","default-src 'self'"),Map.of(),null,"HEAD");
        assertFalse(r.findings.stream().anyMatch(f->f.issueName.contains("frame-ancestors")||f.headerName.equalsIgnoreCase("X-Frame-Options")));
    }
    @Test void fetchedHtmlIsNotAFramedDocument() {
        assertFalse(has(analyze(Map.of("Content-Type","text/html"),Map.of("Sec-Fetch-Dest","empty"),"<form></form>","GET"),"X-Frame-Options"));
    }
    @Test void htmlStringInsideExecutableJsDoesNotHideMimeRisk() {
        assertTrue(has(analyze(Map.of("Content-Type","text/plain"),Map.of("Sec-Fetch-Dest","script"),"const view = '<form></form>'; alert(1);","GET"),"X-Content-Type-Options"));
    }
    @Test void unknownMimeFontKeepsItsExistingNonDocumentFallback() {
        var r=engine.analyze("https://example.test/a.ttf",Map.of(),200,null,"GET");
        assertFalse(has(r,"X-Frame-Options"));
    }
    @Test void attachmentPrefixDoesNotMeanAttachment() {
        assertTrue(has(analyze(Map.of("Content-Type","text/html","Content-Disposition","attachment-example"),Map.of(),"<form></form>","GET"),"X-Frame-Options"));
    }
    @Test void quotedHstsExtensionCanContainSemicolons() {
        assertNull(HeaderReportContext.hsts("max-age=31536000; extension=\"a;b\""));
        assertNotNull(HeaderReportContext.hsts("max-age=31536000; extension=\"unclosed"));
    }
    @Test void blankFirstHstsLineCannotBeReplacedBySecond() {
        var r=analyze(Map.of("Strict-Transport-Security","\nmax-age=31536000"),Map.of(),"body","GET");
        assertTrue(r.findings.stream().anyMatch(f->f.issueName.equals("Invalid HSTS policy")));
    }
    @Test void customHstsRulesAreStillEvaluated() {
        var custom=new RuleDefinition();custom.headerName="Strict-Transport-Security";
        custom.checks.add(new RuleDefinition.CheckDefinition(".*",FieldCheck.TriggerOn.MATCH,"Custom HSTS diagnostic","Custom text",Severity.LOW,Confidence.FIRM,HeaderFinding.Category.CUSTOM));
        rules.add(custom);
        var r=analyze(Map.of("Strict-Transport-Security","max-age=31536000"),Map.of(),"body","GET");
        assertTrue(r.findings.stream().anyMatch(f->f.issueName.equals("Custom HSTS diagnostic")));
    }
    @Test void inertMetaCannotDowngradeReferrerHeaderFinding() {
        var r=analyze(Map.of("Content-Type","text/html","Referrer-Policy","unsafe-url"),Map.of(),
                "<template><meta name=referrer content=no-referrer></template><a href='https://other.test'>link</a>","GET");
        assertTrue(r.findings.stream().anyMatch(f->f.issueName.equals("Referrer-Policy set to unsafe-url")));
    }
    @Test void probeAndControlUrlsCannotReenterBodyAnalyzers() {
        var headers=Map.of("Content-Type","text/html","Cache-Control","public");
        var body="<script>document.cookie='session=abcdefgh12345678';</script>";
        // A probe response can contain a real response-header disclosure, but its synthetic
        // request must never re-enter cookie/storage/auth analysis.
        assertTrue(analyze(headers,Map.of("X-Quimera-Internal-Probe","1"),body,"GET").findings.stream()
                .allMatch(f -> f.category == HeaderFinding.Category.INFORMATION_DISCLOSURE));
        assertTrue(engine.analyze("https://example.test/quimera/collect",headers,Map.of(),200,body,"GET").findings.isEmpty());
        assertTrue(engine.analyzeCredentialBodies("https://example.test/quimera/collect",headers,Map.of(),body,body).isEmpty());
    }
    @Test void cacheDirectivesUseQuotedParsingWithoutRegexStackGrowth() {
        String quoted="x=\""+"x;\\\"y,".repeat(4000)+"\", no-store";
        assertDoesNotThrow(()->assertTrue(CachePolicy.parse(Map.of("Cache-Control",quoted)).has("no-store")));
    }
    @Test void analystBaselineStillProducesFindings() {
        assertTrue(has(analyze(Map.of("Content-Type","text/html"),Map.of("X-Quimera-Internal-Probe","baseline"),"<form></form>","GET"),"X-Frame-Options"));
    }
    @Test void longHstsAndHtmlPreamblesDoNotOverflow() {
        assertDoesNotThrow(()->assertNull(HeaderReportContext.hsts("max-age=31536000; ext=\""+"a".repeat(32000)+"\"")));
        assertDoesNotThrow(()->assertTrue(HeaderReportContext.html("<!--comment-->".repeat(12000)+"<html>")));
        assertFalse(CachePolicy.parse(Map.of("Cache-Control","s-maxage=\"600")).fresh("s-maxage"));
    }

    @Test void markupInAttributesAndRawTextIsNotActiveMetaOrInterface() {
        String body="<div data-example=\"<meta name=referrer content=no-referrer>\"></div><script>const view='<form></form>';</script>";
        assertFalse(HeaderReportContext.interfaceBody(body));
        var r=analyze(Map.of("Content-Type","text/html","Referrer-Policy","unsafe-url"),Map.of(),body,"GET");
        assertTrue(r.findings.stream().anyMatch(f->f.issueName.equals("Referrer-Policy set to unsafe-url")));
    }

}
