package com.b3xal.headeranalyzer.scanner;

import com.b3xal.headeranalyzer.model.UrlAnalysisResult;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NativeIssueDeduplicatorTest {
    @Test
    void secondClaimOfTheSameHostAndTitleIsRejected() {
        String host = "dedup-test-host-1.example";
        String title = "HTTP cache key disclosed through debug response";
        assertTrue(NativeIssueDeduplicator.first(host, title));
        assertFalse(NativeIssueDeduplicator.first(host, title));
    }

    /** Regression: NativeProbeIssuePublisher used to claim the exact same (host, title) key as
     * HeaderPassiveScanner's independent, synchronous publishing path. HeaderPassiveScanner fires
     * on ordinary traffic and is always faster than an active probe (several sequential requests),
     * so it claimed the slot first with whatever incidental evidence it happened to see (e.g. a
     * 404 to an endpoint that discloses the cache key unconditionally), permanently blocking the
     * probe's own, actively-verified 200-status evidence for a completely different URL from ever
     * reaching native Issues under the same title. The "active-probe::" prefix namespaces the two
     * apart so neither can starve the other. */
    @Test
    void activeProbeNamespaceDoesNotCollideWithPlainPassiveClaim() {
        String host = "dedup-test-host-2.example";
        String title = "HTTP cache key disclosed through debug response";

        assertTrue(NativeIssueDeduplicator.first(host, title),
                "passive scanner claims the plain key first, as it does in practice");
        assertTrue(NativeIssueDeduplicator.first(host, "active-probe::" + title),
                "the active probe's own namespaced key must still succeed afterward");
    }

    @Test
    void nativeProbeIdentityPreservesQueryString() {
        UrlAnalysisResult result = new UrlAnalysisResult(
                "https://example.test/post", "example.test", "/post?postId=4",
                List.of(), Map.of());
        assertTrue(NativeProbeIssuePublisher.affectedUrl(result).endsWith("/post?postId=4"));
    }

    @Test
    void scannerConsolidationKeepsSameTitleOnDifferentUrls() {
        String title = "HTTP cache key disclosed through debug response";
        assertFalse(HeaderPassiveScanner.sameIssueInstance(
                title, "https://example.test/academyLabHeader",
                title, "https://example.test/post?postId=1"));
        assertTrue(HeaderPassiveScanner.sameIssueInstance(
                title, "https://example.test/post?postId=1",
                title, "https://example.test/post?postId=1"));
    }
}
