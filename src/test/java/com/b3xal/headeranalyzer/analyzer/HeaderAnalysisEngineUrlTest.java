package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.config.QuimeraSettings;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HeaderAnalysisEngineUrlTest {
    @Test
    void normalizesUrlWithoutQueryOrFragmentAndKeepsNonDefaultPort() {
        assertEquals("https://example.test:8443/a/b",
                HeaderAnalysisEngine.normalizeUrl("https://example.test:8443/a/b?q=1#part"));
        assertEquals("https://example.test/", HeaderAnalysisEngine.normalizeUrl("https://example.test"));
    }

    @Test
    void extractsHostAndPath() {
        assertEquals("example.test", HeaderAnalysisEngine.extractHost("https://example.test/a"));
        assertEquals("/a", HeaderAnalysisEngine.extractPath("https://example.test/a?q=1"));
    }

    @Test
    void malformedInputFallsBackSafely() {
        assertEquals("not a url", HeaderAnalysisEngine.normalizeUrl("not a url"));
        assertEquals("not a url", HeaderAnalysisEngine.extractHost("not a url"));
        assertEquals("/", HeaderAnalysisEngine.extractPath("not a url"));
    }

    @Test
    void extractPathAndQueryKeepsTheQueryStringUnlikeExtractPath() {
        assertEquals("/post?postId=4",
                HeaderAnalysisEngine.extractPathAndQuery("https://example.test/post?postId=4"));
        assertEquals("/a", HeaderAnalysisEngine.extractPathAndQuery("https://example.test/a"));
        assertEquals("/", HeaderAnalysisEngine.extractPathAndQuery("not a url"));
    }

    /** Regression: UrlAnalysisResult.path (and therefore rowKey()/Logger row identity) used to
     * come from extractPath(), which strips the query string. Every query-string variant of an
     * endpoint (?postId=1, ?postId=2, ...) collapsed onto the exact same Logger row/IssueGroup
     * entry, so a LATER sighting of the same bare path (a different postId, or even an unrelated
     * 404 to the same path with no query at all) silently overwrote an EARLIER one's stored
     * request/response and findings, e.g. an active cache-key probe's disclosure on ?postId=4
     * getting clobbered by whatever next hit /post, making the finding look like it "only shows
     * on a 404" once the analyst clicks back into that row. */
    @Test
    void differentQueryStringsOnTheSamePathProduceDistinctRowIdentities() {
        HeaderAnalysisEngine engine = new HeaderAnalysisEngine(new RuleStore(null), new QuimeraSettings());
        var post4 = engine.analyze("https://example.test/post?postId=4",
                Map.of("Content-Type", "text/html"), 200, "GET");
        var post5 = engine.analyze("https://example.test/post?postId=5",
                Map.of("Content-Type", "text/html"), 200, "GET");
        var bareNotFound = engine.analyze("https://example.test/post",
                Map.of("Content-Type", "text/html"), 404, "GET");

        assertEquals("/post?postId=4", post4.path);
        assertEquals("/post?postId=5", post5.path);
        assertEquals("/post", bareNotFound.path);
        assertNotEquals(post4.rowKey(), post5.rowKey());
        assertNotEquals(post4.rowKey(), bareNotFound.rowKey());
    }

    @Test
    void identifiesOnlyQuimeraControlPathAndChildren() {
        assertTrue(HeaderAnalysisEngine.isQuimeraInternalUrl("http://127.0.0.1:8199/quimera"));
        assertTrue(HeaderAnalysisEngine.isQuimeraInternalUrl(
                "http://127.0.0.1:8199/quimera/v1/ingest?source=browser"));
        assertTrue(HeaderAnalysisEngine.isQuimeraInternalUrl("https://example.test/QUIMERA/v1/ping"));
        assertFalse(HeaderAnalysisEngine.isQuimeraInternalUrl("https://example.test/quimera-app"));
        assertFalse(HeaderAnalysisEngine.isQuimeraInternalUrl("https://example.test/app/quimera"));
    }
}
