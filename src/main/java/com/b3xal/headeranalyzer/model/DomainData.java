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
    // Disclosure is historical host inventory: a later response for the same path may omit a
    // header that was genuinely exposed earlier. urlResults intentionally keeps only the latest
    // row, so retain the first representative and every affected row key separately.
    private final ConcurrentHashMap<String, HeaderFinding> disclosureInventory = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Set<String>> disclosureRows = new ConcurrentHashMap<>();
    // Same "survives being overwritten by a later, cleaner response" reasoning as
    // disclosureInventory above, applied to COOKIE findings: a cookie flag issue is usually only
    // observable on the specific login/auth response that issues the Set-Cookie, a DIFFERENT URL
    // from whichever page an analyst has selected in the Logger, and urlResults alone (latest
    // result per path) would silently drop it the moment that path is revisited without it.
    // Keyed by aggregationKey() alone (issueName+headerName), NOT disclosureKey(): cookie
    // issueNames already embed the cookie name ("Cookie missing Secure flag: session_id"), so
    // aggregationKey() is already fully distinguishing, and a cookie's raw Set-Cookie value
    // commonly rotates per request (session tokens), keying on it like disclosureKey() does would
    // defeat dedup entirely and show the same underlying issue as endless "new" entries.
    private final ConcurrentHashMap<String, HeaderFinding> cookieInventory = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Set<String>> cookieRows = new ConcurrentHashMap<>();

    public DomainData(String host) {
        this.host = host;
    }

    public void addResult(UrlAnalysisResult result) {
        for (HeaderFinding finding : result.findings) {
            if (finding.category == HeaderFinding.Category.INFORMATION_DISCLOSURE) {
                String key = disclosureKey(finding);
                disclosureInventory.putIfAbsent(key, finding);
                disclosureRows.computeIfAbsent(key, ignored -> ConcurrentHashMap.newKeySet())
                        .add(result.rowKey());
            } else if (finding.category == HeaderFinding.Category.COOKIE) {
                String key = finding.aggregationKey();
                cookieInventory.putIfAbsent(key, finding);
                cookieRows.computeIfAbsent(key, ignored -> ConcurrentHashMap.newKeySet())
                        .add(result.rowKey());
            }
        }
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

    // ------ Domain-level summary: missing headers across all pages ------------------------------------------------

    /** How many unique paths have been analyzed. */
    public int getPathCount() {
        return urlResults.size();
    }

    /** De-duplicated technology inventory aggregated across every URL of this host. */
    public List<TechFinding> getTechInventory() {
        return TechInventory.aggregate(urlResults.values());
    }

    public Collection<HeaderFinding> getDisclosureInventory() {
        return Collections.unmodifiableCollection(disclosureInventory.values());
    }

    public int getDisclosureObservationCount(HeaderFinding finding) {
        Set<String> rows = disclosureRows.get(disclosureKey(finding));
        return rows == null ? 0 : rows.size();
    }

    public Collection<HeaderFinding> getCookieInventory() {
        return Collections.unmodifiableCollection(cookieInventory.values());
    }

    public int getCookieObservationCount(HeaderFinding finding) {
        Set<String> rows = cookieRows.get(finding.aggregationKey());
        return rows == null ? 0 : rows.size();
    }

    private static String disclosureKey(HeaderFinding finding) {
        return finding.aggregationKey() + "|" +
                (finding.headerValue == null ? "" : finding.headerValue);
    }

    // ------ Inner classes ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------

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
