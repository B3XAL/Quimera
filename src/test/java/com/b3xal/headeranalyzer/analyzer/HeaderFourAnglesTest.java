package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.config.QuimeraSettings;
import com.b3xal.headeranalyzer.model.*;
import com.b3xal.headeranalyzer.util.HeaderMaps;
import org.junit.jupiter.api.Test;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class HeaderFourAnglesTest {
    final RuleStore rules = new RuleStore(null);
    final HeaderAnalysisEngine engine = new HeaderAnalysisEngine(rules, new QuimeraSettings());
    UrlAnalysisResult analyze(Map<String,String> headers, String body) {
        return engine.analyze("https://example.test/page", headers, Map.of(), 200, body, "GET");
    }
    @Test void firstEmptyHstsSurvivesTheRealHeaderCollector() {
        Map<String,String> headers = new LinkedHashMap<>();
        HeaderMaps.addResponse(headers,"Strict-Transport-Security","");
        HeaderMaps.addResponse(headers,"strict-transport-security","max-age=31536000");
        assertTrue(analyze(headers,"body").findings.stream().anyMatch(f -> f.headerName.equalsIgnoreCase("Strict-Transport-Security")));
    }
    @Test void namespacedAttributesAreNotReferrerMetadata() {
        assertUnsafeMeta("<meta x:name=referrer x:content=no-referrer>");
    }
    @Test void firstBooleanAttributeWinsOverDuplicateValue() {
        assertUnsafeMeta("<meta name name=referrer content=no-referrer>");
    }
    @Test void whitespaceInMetaPolicyIsNotSilentlyTrimmed() {
        assertUnsafeMeta("<meta name=referrer content=' no-referrer '>");
    }
    private void assertUnsafeMeta(String body) {
        assertTrue(analyze(Map.of("Content-Type","text/html","Referrer-Policy","unsafe-url"),body)
                .findings.stream().anyMatch(f -> f.issueName.equals("Referrer-Policy set to unsafe-url")));
    }
    @Test void varyWildcardDoesNotPermitUnvalidatedSharedReuse() {
        assertFalse(CachePolicy.parse(Map.of("Cache-Control","public, max-age=600","Vary","Accept, *")).sharedReuseAllowed(Map.of()));
    }
    @Test void missingCacheOnHeadDoesNotInferSensitiveRepresentationFromImpossibleBody() {
        var r=engine.analyze("https://example.test/a",Map.of(),Map.of(),200,"{\"password\":\"secret123\"}","HEAD");
        assertFalse(r.findings.stream().anyMatch(f->f.issueName.equals("Missing Cache-Control header")));
    }
    @Test void customMimeRuleSurvivesFullAnalysis() {
        var custom = new RuleDefinition(); custom.headerName="X-Content-Type-Options";
        custom.checks.add(new RuleDefinition.CheckDefinition(".*",FieldCheck.TriggerOn.MATCH,"Analyst MIME rule","Explicit rule",Severity.MEDIUM,Confidence.FIRM,HeaderFinding.Category.CUSTOM));
        rules.add(custom);
        assertTrue(analyze(Map.of("Content-Type","image/png","X-Content-Type-Options","nosniff"),"PNG")
                .findings.stream().anyMatch(f->f.issueName.equals("Analyst MIME rule")));
    }
    @Test void customXfoRuleSurvivesCspMitigation() {
        var custom = new RuleDefinition(); custom.headerName="X-Frame-Options";
        custom.checks.add(new RuleDefinition.CheckDefinition(".*",FieldCheck.TriggerOn.MATCH,"Analyst XFO rule","Explicit rule",Severity.MEDIUM,Confidence.FIRM,HeaderFinding.Category.CUSTOM));
        rules.add(custom);
        assertTrue(analyze(Map.of("Content-Type","text/html","X-Frame-Options","DENY","Content-Security-Policy","frame-ancestors 'none'"),"<form>")
                .findings.stream().anyMatch(f->f.issueName.equals("Analyst XFO rule")));
    }
    @Test void longVersionLabelsDoNotOverflow() {
        HeaderFinding f=new HeaderFinding("Version observed","X-Version","", "", "",Severity.INFORMATION,Confidence.CERTAIN,HeaderFinding.Category.INFORMATION_DISCLOSURE);
        assertDoesNotThrow(()->HeaderReportContext.apply(List.of(f),Map.of("X-Version","1.".repeat(10000)+"1"),Map.of(),"https://example.test",200,null,"GET"));
    }
    @Test void longServerVersionsDoNotOverflow() {
        assertDoesNotThrow(()->assertTrue(HeaderReportContext.serverVersion("nginx/"+"1.".repeat(10000)+"1")));
    }
    @Test void hstsTokenExtensionMayContainAnAsterisk() {
        assertNull(HeaderReportContext.hsts("max-age=31536000; ext*=value"));
    }
    @Test void aggregateRetainsDifferentEvidenceAndStrongestSeverity() {
        DomainData domain=new DomainData("example.test");
        for(int i=0;i<2;i++) {
            HeaderFinding f=new HeaderFinding("Missing HSTS","Strict-Transport-Security",null,"description "+i,"evidence "+i,i==0?Severity.INFORMATION:Severity.MEDIUM,Confidence.CERTAIN,HeaderFinding.Category.SECURITY_MISSING);
            domain.addResult(new UrlAnalysisResult("https://example.test/"+i,"example.test","/"+i,List.of(f),Map.of()));
        }
        var aggregate=domain.getAggregateFindings().get(0);
        assertEquals(Severity.MEDIUM,aggregate.severity);
        assertEquals(Set.of("evidence 0","evidence 1"),new HashSet<>(aggregate.evidenceSamples));
    }
    @Test void traceConfirmationDoesNotSuppressADifferentQuery() {
        DomainData domain=new DomainData("example.test");
        for(int i=1;i<=2;i++) {
            String title=i==1?"TRACE method enabled (request echoed by server)":"HTTP TRACE method advertised";
            var f=new HeaderFinding(title,"Allow","TRACE","desc","evidence",Severity.LOW,Confidence.CERTAIN,HeaderFinding.Category.ACTIVE);
            var r=new UrlAnalysisResult("https://example.test/a","example.test","/a?id="+i,List.of(f),Map.of());
            r.probeLabel=i==1?"TRACE probe":null;
            domain.addResult(r);
        }
        assertEquals(2,domain.getAggregateFindings().size());
        assertTrue(domain.getAggregateFindings().stream().flatMap(f->f.affectedUrls.stream()).anyMatch(u->u.endsWith("?id=2")));
    }
    @Test void userRuleCategoryAndSeveritySurviveContextAndPersistence() {
        var custom=new RuleDefinition();custom.headerName="X-Frame-Options";
        custom.checks.add(new RuleDefinition.CheckDefinition(".*",FieldCheck.TriggerOn.MATCH,"Custom security check","Explicit",Severity.HIGH,Confidence.FIRM,HeaderFinding.Category.SECURITY_MISCONFIGURED));
        rules.add(custom);
        var r=analyze(Map.of("X-Frame-Options","DENY","Content-Type","image/png"),"PNG");
        var store=new ResultStore(null,null);
        var restored=store.fromJson(store.toJson(r));
        var finding=restored.findings.stream().filter(f->f.issueName.equals("Custom security check")).findFirst().orElseThrow();
        assertEquals(Severity.HIGH,finding.severity);
        assertEquals(HeaderFinding.Category.SECURITY_MISCONFIGURED,finding.category);
        assertTrue(finding.isUserDefined());
        custom.enabled=false;
        assertFalse(analyze(Map.of("X-Frame-Options","DENY"),"body").findings.stream().anyMatch(f->f.issueName.equals("Custom security check")));
    }
    @Test void invalidNoMatchRegexCannotBecomeAVulnerability() {
        var custom=new RuleDefinition();custom.headerName="X-Test";
        custom.checks.add(new RuleDefinition.CheckDefinition("[",FieldCheck.TriggerOn.NO_MATCH,"Broken regex finding","Explicit",Severity.HIGH,Confidence.FIRM,HeaderFinding.Category.CUSTOM));
        rules.add(custom);
        assertFalse(analyze(Map.of("X-Test","value"),"body").findings.stream().anyMatch(f->f.issueName.equals("Broken regex finding")));
    }

    @Test void longDiagnosticHeadersSurviveTheWholePipeline() {
        assertDoesNotThrow(()->analyze(Map.of("Server","nginx/"+"1.".repeat(10000)+"1", "X-Version","1.".repeat(10000)+"1"),"body"));
    }
    @Test void customMissingHstsOnHttpKeepsTheAnalystsIntent() {
        var custom=new RuleDefinition();custom.headerName="Strict-Transport-Security";
        custom.mandatory=true;custom.missingIssueName="Custom missing HSTS";custom.missingDescription="Explicit";
        custom.missingSeverity=Severity.INFORMATION;custom.missingConfidence=Confidence.FIRM;custom.missingCategory=HeaderFinding.Category.ADVISABLE;
        rules.add(custom);
        assertTrue(engine.analyze("http://example.test/",Map.of(),Map.of(),200,"body","GET").findings.stream().anyMatch(f->f.issueName.equals("Custom missing HSTS")));
    }
    @Test void traceAnnouncementIsSuppressedOnlyForTheConfirmedQuery() {
        DomainData domain=new DomainData("example.test");
        for(int i=0;i<2;i++) {
            var f=new HeaderFinding(i==0?"HTTP TRACE method advertised":"TRACE method enabled (request echoed by server)","Allow","TRACE","desc","evidence",Severity.LOW,Confidence.CERTAIN,HeaderFinding.Category.ACTIVE);
            var r=new UrlAnalysisResult("https://example.test/a","example.test","/a?id=1",List.of(f),Map.of());
            r.probeLabel=i==0?null:"TRACE probe";
            domain.addResult(r);
        }
        assertEquals(1,domain.getAggregateFindings().size());
        assertEquals("TRACE method enabled (request echoed by server)",domain.getAggregateFindings().get(0).issueName);
    }

    @Test void customElementPrefixesAreNotNativeHtmlElements() {
        assertUnsafeMeta("<meta-widget name=referrer content=no-referrer></meta-widget>");
        assertFalse(HeaderReportContext.interfaceBody("<form-widget></form-widget>"));
    }

}
