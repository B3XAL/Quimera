package com.b3xal.headeranalyzer.model;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Aggregates all URL results for a single host/domain.
 * Provides domain-level findings (cross-URL view) and per-URL access.
 */
public class DomainData {

    public final String host;
    // path (normalized) → result
    private final ConcurrentHashMap<String, UrlAnalysisResult> urlResults = new ConcurrentHashMap<>();

    public DomainData(String host) {
        this.host = host;
    }

    public void addResult(UrlAnalysisResult result) {
        urlResults.put(result.rowKey(), result);
    }

    public Map<String, UrlAnalysisResult> getUrlResults() {
        return Collections.unmodifiableMap(urlResults);
    }

    public Severity getWorstSeverity() {
        return urlResults.values().stream()
                .map(UrlAnalysisResult::getWorstSeverity)
                .min(Comparator.comparingInt(s -> s.order))
                .orElse(Severity.INFORMATION);
    }

    public int getTotalFindings() {
        return urlResults.values().stream()
                .mapToInt(r -> r.findings.size())
                .sum();
    }

    /**
     * Aggregate findings across all URLs.
     * Groups by aggregationKey() and collects affected URLs.
     * Findings seen on more URLs get stronger aggregated evidence.
     */
    public List<AggregateFinding> getAggregateFindings() {
        // key → {finding, list of URLs}
        Map<String, AggregateFindingBuilder> builders = new LinkedHashMap<>();

        for (UrlAnalysisResult result : urlResults.values()) {
            for (HeaderFinding f : result.findings) {
                String key = f.aggregationKey();
                builders.computeIfAbsent(key, k -> new AggregateFindingBuilder(f))
                        .addUrl(result.url);
            }
        }

        return builders.values().stream()
                .map(AggregateFindingBuilder::build)
                .sorted(Comparator.comparingInt(af -> af.severity.order))
                .collect(Collectors.toList());
    }

    // ── Domain-level summary: missing headers across all pages ────────────────

    /** How many unique paths have been analyzed. */
    public int getPathCount() {
        return urlResults.size();
    }

    /** De-duplicated technology inventory aggregated across every URL of this host. */
    public List<TechFinding> getTechInventory() {
        return TechInventory.aggregate(urlResults.values());
    }

    // ── Inner classes ─────────────────────────────────────────────────────────

    /** A finding aggregated across multiple URLs of this domain. */
    public static class AggregateFinding {
        public final String issueName;
        public final String headerName;
        public final Severity severity;
        public final Confidence confidence;
        public final HeaderFinding.Category category;
        public final String description;
        public final List<String> affectedUrls;   // sorted
        public final List<String> evidenceSamples; // up to 3 distinct header values seen

        public AggregateFinding(String issueName, String headerName,
                                Severity severity, Confidence confidence,
                                HeaderFinding.Category category, String description,
                                List<String> affectedUrls, List<String> evidenceSamples) {
            this.issueName      = issueName;
            this.headerName     = headerName;
            this.severity       = severity;
            this.confidence     = confidence;
            this.category       = category;
            this.description    = description;
            this.affectedUrls   = Collections.unmodifiableList(new ArrayList<>(affectedUrls));
            this.evidenceSamples = Collections.unmodifiableList(new ArrayList<>(evidenceSamples));
        }

        public String getAffectedSummary() {
            int n = affectedUrls.size();
            return n == 1 ? "1 URL" : n + " URLs";
        }
    }

    private static class AggregateFindingBuilder {
        private final HeaderFinding proto;
        private final List<String> urls = new ArrayList<>();
        private final LinkedHashSet<String> evidenceSamples = new LinkedHashSet<>();

        AggregateFindingBuilder(HeaderFinding proto) {
            this.proto = proto;
        }

        void addUrl(String url) {
            if (!urls.contains(url)) urls.add(url);
            if (proto.evidence != null && evidenceSamples.size() < 3) {
                evidenceSamples.add(proto.evidence);
            }
        }

        AggregateFinding build() {
            Collections.sort(urls);
            return new AggregateFinding(
                    proto.issueName, proto.headerName,
                    proto.severity, proto.confidence,
                    proto.category, proto.description,
                    urls, new ArrayList<>(evidenceSamples));
        }
    }
}
