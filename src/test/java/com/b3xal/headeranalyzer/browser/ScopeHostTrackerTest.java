package com.b3xal.headeranalyzer.browser;

import org.junit.jupiter.api.Test;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ScopeHostTrackerTest {
    @Test
    void returnsOnlyObservedUrlsThatAreCurrentlyInScope() {
        Set<String> scoped = ConcurrentHashMap.newKeySet();
        scoped.add("https://shop.example.test/account");
        ScopeHostTracker tracker = new ScopeHostTracker(scoped::contains);
        tracker.observe("https://shop.example.test/account");
        tracker.observe("https://cdn.example.test/app.js");
        tracker.observe("file:///tmp/not-http");

        assertEquals(java.util.List.of("shop.example.test"), tracker.inScopeHosts());
        assertEquals(java.util.List.of("shop.example.test"), tracker.snapshot().hosts());

        scoped.clear();
        scoped.add("https://cdn.example.test/app.js");
        ScopeHostTracker.ScopeSnapshot changed = tracker.snapshot();
        assertEquals(java.util.List.of("cdn.example.test"), changed.hosts());
        assertEquals(java.util.List.of("shop.example.test"), changed.removedHosts());
    }

    @Test
    void deduplicatesHostsAndIgnoresMalformedUrls() {
        ScopeHostTracker tracker = new ScopeHostTracker(url -> true);
        tracker.observe("https://example.test/a");
        tracker.observe("https://example.test/b");
        tracker.observe("not a URL");

        assertEquals(java.util.List.of("example.test"), tracker.inScopeHosts());
        assertEquals(2, tracker.observedUrlCount());
    }
}
