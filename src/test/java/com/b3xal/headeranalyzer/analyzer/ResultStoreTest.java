package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.model.Confidence;
import com.b3xal.headeranalyzer.model.HeaderFinding;
import com.b3xal.headeranalyzer.model.Severity;
import com.b3xal.headeranalyzer.model.TechFinding;
import com.b3xal.headeranalyzer.model.UrlAnalysisResult;
import com.b3xal.headeranalyzer.persistence.ExternalEvidenceArchive;
import com.b3xal.headeranalyzer.config.QuimeraSettings;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
    @TempDir Path temporaryDirectory;

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
        HeaderFinding finding = new HeaderFinding("Intermediary routing metadata observed", "Via", "1.1 proxy",
                "desc", "evidence", Severity.INFORMATION, Confidence.CERTAIN,
                HeaderFinding.Category.INFORMATION_DISCLOSURE);
        UrlAnalysisResult original = new UrlAnalysisResult("https://example.test/", "example.test", "/",
                List.of(finding), Map.of());

        UrlAnalysisResult restored = store.fromJson(store.toJson(original));
        assertNull(restored.findings.get(0).referenceUrl);
    }

    @Test
    void retiredBuiltinNoiseDoesNotReappearFromPersistedHistory() {
        HeaderFinding retired = new HeaderFinding("Cache status disclosure", "X-Cache-Hit", "true",
                "old", "old", Severity.INFORMATION, Confidence.CERTAIN,
                HeaderFinding.Category.INFORMATION_DISCLOSURE);
        HeaderFinding retained = new HeaderFinding("Missing Content Security Policy", "Content-Security-Policy", null,
                "real", "real", Severity.MEDIUM, Confidence.CERTAIN,
                HeaderFinding.Category.SECURITY_MISSING);
        UrlAnalysisResult original = new UrlAnalysisResult("https://example.test/", "example.test", "/",
                List.of(retired, retained), Map.of());

        UrlAnalysisResult restored = store.fromJson(store.toJson(original));
        assertEquals(1, restored.findings.size());
        assertEquals("Missing Content Security Policy", restored.findings.get(0).issueName);
    }

    @Test
    void historicalBlankServerDisclosureDoesNotReappear() {
        HeaderFinding obsoleteBlankFinding = new HeaderFinding("Server technology family disclosure", "Server", "",
                "old", "Server:", Severity.LOW, Confidence.CERTAIN,
                HeaderFinding.Category.INFORMATION_DISCLOSURE);
        HeaderFinding realServerDisclosure = new HeaderFinding("Server technology family disclosure", "Server", "nginx",
                "real", "Server: nginx", Severity.LOW, Confidence.CERTAIN,
                HeaderFinding.Category.INFORMATION_DISCLOSURE);
        UrlAnalysisResult original = new UrlAnalysisResult("https://example.test/", "example.test", "/",
                List.of(obsoleteBlankFinding, realServerDisclosure), Map.of());

        UrlAnalysisResult restored = store.fromJson(store.toJson(original));
        assertEquals(1, restored.findings.size());
        assertEquals("nginx", restored.findings.get(0).headerValue);
    }

    @Test
    void malformedJsonReturnsNullInsteadOfThrowing() {
        assertNull(store.fromJson("{not valid json"));
    }

    @Test
    void roundTripsArchivedEvidenceExcerptsWithoutLiveExchange() {
        HeaderFinding finding = new HeaderFinding("AWS access key ID observed in response body", "(response body)",
                "AKIA0123456789ABCDEF", "desc", "evidence", Severity.LOW, Confidence.FIRM,
                HeaderFinding.Category.AUTH);
        UrlAnalysisResult result = new UrlAnalysisResult("https://example.test/error", "example.test", "/error",
                List.of(finding), Map.of());
        result.archivedRequestExcerpt = "POST /error HTTP/1.1\n[archived evidence truncated]";
        result.archivedResponseExcerpt = "HTTP/1.1 500\n...AKIA0123456789ABCDEF...";

        UrlAnalysisResult restored = store.fromJson(store.toJson(result));
        assertEquals(result.archivedRequestExcerpt, restored.archivedRequestExcerpt);
        assertEquals(result.archivedResponseExcerpt, restored.archivedResponseExcerpt);
    }

    @Test
    void roundTripsExternalEvidenceReferenceWithoutEmbeddingTheExchange() {
        HeaderFinding finding = new HeaderFinding("Leak", "(response body)", "value", "desc", "ev",
                Severity.LOW, Confidence.FIRM, HeaderFinding.Category.AUTH);
        UrlAnalysisResult result = new UrlAnalysisResult("https://example.test/error", "example.test", "/error",
                List.of(finding), Map.of());
        result.externalEvidenceReference = new ExternalEvidenceArchive.ArchiveReference("a".repeat(64), 123_456);
        result.externalProbeEvidenceReferences = List.of(
                new ExternalEvidenceArchive.ArchiveReference("b".repeat(64), 12),
                new ExternalEvidenceArchive.ArchiveReference("c".repeat(64), 34));

        UrlAnalysisResult restored = store.fromJson(store.toJson(result));
        assertEquals(result.externalEvidenceReference, restored.externalEvidenceReference);
        assertEquals(result.externalProbeEvidenceReferences, restored.externalProbeEvidenceReferences);
        assertNull(restored.originalRequest);
        assertNull(restored.originalResponse);
    }

    @Test
    void archivedExcerptRetainsDistantEvidenceForMultipleFindings() {
        String first = "AKIA0123456789ABCDEF";
        String second = "AIza" + "a".repeat(35);
        String raw = "HTTP/1.1 500\r\nContent-Type: text/html\r\n\r\n" + first + "x".repeat(30_000) + second;
        String excerpt = ResultStore.excerptAll(raw, 8_000, List.of(first, second));
        assertTrue(excerpt.contains(first));
        assertTrue(excerpt.contains(second));
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

    @Test
    void clearRemovesOnlyThisProjectsExternalArchiveEvenWhenArchiveWritesAreDisabled() throws Exception {
        String projectId = "project-being-cleared";
        QuimeraSettings settings = new QuimeraSettings();
        settings.setExternalEvidenceArchive(false, temporaryDirectory.toString());
        Path archiveRoot = temporaryDirectory.resolve("quimera-evidence");
        Path thisProject = archiveRoot.resolve(projectDirectoryId(projectId));
        Path otherProject = archiveRoot.resolve("another-project");
        Files.createDirectories(thisProject.resolve("objects/ab"));
        Files.writeString(thisProject.resolve("objects/ab/evidence.qev.gz"), "sensitive evidence");
        Files.createDirectories(otherProject);
        Files.writeString(otherProject.resolve("must-survive"), "other project");
        Path userFile = temporaryDirectory.resolve("user-file.txt");
        Files.writeString(userFile, "must-survive");

        new ResultStore(null, null, settings, projectId).clearAll();

        assertFalse(Files.exists(thisProject), "Clear must remove this project's external evidence");
        assertTrue(Files.exists(otherProject.resolve("must-survive")), "other projects must remain untouched");
        assertTrue(Files.exists(userFile), "the user-selected directory itself must remain untouched");
    }

    private static String projectDirectoryId(String projectId) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(projectId.getBytes(StandardCharsets.UTF_8))).substring(0, 32);
    }
}
