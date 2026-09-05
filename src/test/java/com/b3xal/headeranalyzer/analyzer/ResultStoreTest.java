package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.model.Confidence;
import com.b3xal.headeranalyzer.model.HeaderFinding;
import com.b3xal.headeranalyzer.model.Severity;
import com.b3xal.headeranalyzer.model.TechFinding;
import com.b3xal.headeranalyzer.model.UrlAnalysisResult;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ResultStore.persist()/loadInto() themselves call Montoya's PersistedObject.persistedObject()/
 * PersistedList static factories, which require a live Burp instance (their backing
 * ObjectFactoryLocator is only set by Burp itself, confirmed empirically: calling them from a
 * plain JVM throws NullPointerException), so that Montoya-integration plumbing can only be
 * exercised by compilation + code review, same posture already accepted for
 * ActiveHeaderScanner's live-HTTP probe methods. What IS fully testable, and is the actual risk
 * area (a subtly wrong round-trip silently corrupts every restored finding), is the pure
 * JSON metadata serialization and the quota-counting arithmetic, both zero-Montoya-dependency
 * package-private methods.
 */
class ResultStoreTest {
    private final ResultStore store = new ResultStore(null, null);

    @Test
    void roundTripsAllFindingAndTechFindingFields() {
        HeaderFinding finding = new HeaderFinding(
                "Backend IP address disclosure via custom Varnish debug header", "X-Varnish-Ip", "10.0.25.16",
                "Reveals the backend IP.", "X-Varnish-Ip: 10.0.25.16",
                Severity.MEDIUM, Confidence.CERTAIN, HeaderFinding.Category.INFORMATION_DISCLOSURE,
                "https://docs.gitlab.com/user/application_security/dast/browser/checks/16.4/");
        TechFinding tech = new TechFinding("Varnish", "7.1", "Via", "1.1 varnish (Varnish/7.1)");

        UrlAnalysisResult original = new UrlAnalysisResult(
                "https://example.test/x.webp", "example.test", "/x.webp",
                List.of(finding), Map.of("Content-Type", "image/webp"), List.of(tech));
        original.method        = "GET";
        original.statusCode    = 200;
        original.contentLength = 61414;
        original.probeLabel    = null;

        UrlAnalysisResult restored = store.fromJson(store.toJson(original));

        assertEquals(original.url, restored.url);
        assertEquals(original.host, restored.host);
        assertEquals(original.path, restored.path);
        assertEquals(original.method, restored.method);
        assertEquals(original.statusCode, restored.statusCode);
        assertEquals(original.contentLength, restored.contentLength);
        assertEquals("image/webp", restored.rawHeaders.get("Content-Type"));

        assertEquals(1, restored.findings.size());
        HeaderFinding rf = restored.findings.get(0);
        assertEquals(finding.issueName, rf.issueName);
        assertEquals(finding.headerName, rf.headerName);
        assertEquals(finding.headerValue, rf.headerValue);
        assertEquals(finding.description, rf.description);
        assertEquals(finding.evidence, rf.evidence);
        assertEquals(finding.severity, rf.severity);
        assertEquals(finding.confidence, rf.confidence);
        assertEquals(finding.category, rf.category);
        assertEquals(finding.referenceUrl, rf.referenceUrl);

        assertEquals(1, restored.techFindings.size());
        TechFinding rt = restored.techFindings.get(0);
        assertEquals(tech.product, rt.product);
        assertEquals(tech.version, rt.version);
        assertEquals(tech.sourceHeader, rt.sourceHeader);
        assertEquals(tech.rawValue, rt.rawValue);
    }

    /** referenceUrl is nullable (see HeaderFinding's own javadoc, "deliberately rare"), the
     * common case, so the round-trip must not choke on or corrupt a null into the literal
     * string "null". */
    @Test
    void nullReferenceUrlSurvivesTheRoundTrip() {
        HeaderFinding finding = new HeaderFinding("Cache infrastructure disclosure", "X-Cache", "HIT",
                "desc", "evidence", Severity.INFORMATION, Confidence.CERTAIN,
                HeaderFinding.Category.INFORMATION_DISCLOSURE);
        UrlAnalysisResult original = new UrlAnalysisResult("https://example.test/", "example.test", "/",
                List.of(finding), Map.of());

        UrlAnalysisResult restored = store.fromJson(store.toJson(original));
        assertNull(restored.findings.get(0).referenceUrl);
    }

    @Test
    void malformedJsonReturnsNullInsteadOfThrowing() {
        assertNull(store.fromJson("{not valid json"));
    }

    // ------ Quota arithmetic (the "12000 identical Last-Modified findings" case) --------------

    @Test
    void quotaIsAvailableUntilTheCapThenExhausted() {
        HeaderFinding lastModified = new HeaderFinding(
                "Content modification timestamp disclosure", "Last-Modified", "Thu, 11 Dec 2025 17:25:51 GMT",
                "desc", "evidence", Severity.LOW, Confidence.CERTAIN, HeaderFinding.Category.INFORMATION_DISCLOSURE);
        UrlAnalysisResult result = new UrlAnalysisResult("https://example.test/a.webp", "example.test", "/a.webp",
                List.of(lastModified), Map.of());

        // Manually drive the counter the same way persist() would for 200 prior sightings.
        for (int i = 0; i < 200; i++) {
            assertTrue(store.hasQuotaRemaining(result), "should still have quota at sighting #" + i);
            store.countKey("example.test", lastModified).incrementAndGet();
        }
        assertTrue(!store.hasQuotaRemaining(result), "quota must be exhausted after 200 sightings");
    }

    /** The exact scenario the user raised: a rare finding riding along on the same response as a
     * common, already-exhausted one must still get its own quota, not be starved by the other. */
    @Test
    void aRareFindingIsNotStarvedByACommonExhaustedOneOnTheSameRow() {
        HeaderFinding common = new HeaderFinding("Content modification timestamp disclosure", "Last-Modified",
                "v", "d", "e", Severity.LOW, Confidence.CERTAIN, HeaderFinding.Category.INFORMATION_DISCLOSURE);
        HeaderFinding rare = new HeaderFinding("Akamai internal property variable values disclosed via debug header",
                "X-Akamai-Session-Info", "v", "d", "e", Severity.MEDIUM, Confidence.CERTAIN,
                HeaderFinding.Category.INFORMATION_DISCLOSURE);

        for (int i = 0; i < 200; i++) store.countKey("example.test", common).incrementAndGet();

        UrlAnalysisResult result = new UrlAnalysisResult("https://example.test/b", "example.test", "/b",
                List.of(common, rare), Map.of());
        assertTrue(store.hasQuotaRemaining(result), "the rare finding's own quota must still be available");
    }
}
