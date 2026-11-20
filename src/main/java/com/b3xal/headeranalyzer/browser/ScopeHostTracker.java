package com.b3xal.headeranalyzer.browser;

import java.net.URI;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;

/** Bounded index used to derive browser hosts from URLs observed and currently in Burp scope. */
public final class ScopeHostTracker {
    private static final int MAX_OBSERVED_URLS = 5_000;
    private static final int MAX_SCOPE_HOSTS = 500;

    private final Predicate<String> isInScope;
    private Set<String> previousScopeHosts = Set.of();
    private final Map<String, String> observed = new LinkedHashMap<>(256, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, String> eldest) {
            return size() > MAX_OBSERVED_URLS;
        }
    };

    public ScopeHostTracker(Predicate<String> isInScope) {
        this.isInScope = isInScope;
    }

    public synchronized void observe(String rawUrl) {
        if (rawUrl == null || rawUrl.isBlank()) return;
        try {
            URI uri = URI.create(rawUrl);
            String scheme = uri.getScheme();
            String host = uri.getHost();
            if (scheme == null || host == null
                    || !(scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase("https"))) return;
            observed.put(rawUrl, host.toLowerCase(Locale.ROOT));
        } catch (IllegalArgumentException ignored) {
            // Malformed/non-HTTP traffic is not a browser host candidate.
        }
    }

    public synchronized List<String> inScopeHosts() {
        Set<String> hosts = new LinkedHashSet<>();
        for (Map.Entry<String, String> entry : new ArrayList<>(observed.entrySet())) {
            if (isInScope.test(entry.getKey())) hosts.add(entry.getValue());
            if (hosts.size() >= MAX_SCOPE_HOSTS) break;
        }
        return hosts.stream().sorted(Comparator.naturalOrder()).toList();
    }

    public synchronized ScopeSnapshot snapshot() {
        List<String> hosts = inScopeHosts();
        Set<String> current = new LinkedHashSet<>(hosts);
        List<String> removed = previousScopeHosts.stream()
                .filter(host -> !current.contains(host))
                .sorted()
                .toList();
        previousScopeHosts = Set.copyOf(current);
        return new ScopeSnapshot(hosts, removed);
    }

    public record ScopeSnapshot(List<String> hosts, List<String> removedHosts) {
        public static ScopeSnapshot empty() {
            return new ScopeSnapshot(List.of(), List.of());
        }
    }

    synchronized int observedUrlCount() {
        return observed.size();
    }
}
