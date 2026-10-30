package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.model.FindingStatus;
import com.b3xal.headeranalyzer.model.HeaderFinding;
import com.b3xal.headeranalyzer.model.RetestRecord;
import com.b3xal.headeranalyzer.model.UrlAnalysisResult;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Tracks the verification state of findings across time so Quimera can answer "is this still
 * broken?" instead of just "what did we see this one time".
 *
 * Two ways a finding's status changes:
 *   1. Automatically, whenever a full (non-probe) analysis result comes in for a URL, if a
 *      previously OPEN finding for that exact URL no longer appears, it's marked RESOLVED with no
 *      user action required (e.g. simply re-browsing the page after a fix ships resolves it).
 *   2. Explicitly, via the UI's "Retest selected" action, which sends a fresh request for the
 *      affected URL(s) and reconciles the same way, this just gives the user an on-demand trigger
 *      instead of waiting for new traffic.
 *
 * If a RESOLVED finding is later observed present again, it flips to REOPENED, a signal that a
 * fix regressed, which is valuable to call out in a report.
 */
public class RetestTracker {

    private final Map<String, RetestRecord> records = new ConcurrentHashMap<>();

    public static String key(String host, String path, String issueName, String headerName) {
        return host + "|" + path + "|" + issueName + "|" + headerName;
    }

    public static String key(String host, String path, HeaderFinding f) {
        return key(host, path, f.issueName, f.headerName);
    }

    /**
     * Reconciles tracked state against a fresh, full analysis of one URL. Probe results
     * (OPTIONS/TRACE/HSTS, partial views of the response) are ignored: only a normal GET/passive
     * capture reflects the "complete" set of header findings for that URL.
     */
    public void reconcile(UrlAnalysisResult result) {
        if (result.probeLabel != null) return;

        LocalDateTime now = LocalDateTime.now();
        Set<String> present = new HashSet<>();

        for (HeaderFinding f : result.findings) {
            String k = key(result.host, result.path, f);
            present.add(k);
            RetestRecord r = records.computeIfAbsent(k, RetestRecord::new);
            if (r.status == FindingStatus.RESOLVED) {
                r.status = FindingStatus.REOPENED;
            } else if (r.status == FindingStatus.REOPENED) {
                // still open, no change
            } else {
                r.status = FindingStatus.OPEN;
            }
            r.lastSeen = now;
            r.lastChecked = now;
        }

        String prefix = result.host + "|" + result.path + "|";
        for (RetestRecord r : records.values()) {
            if (!r.key.startsWith(prefix)) continue;
            if (present.contains(r.key)) continue;
            if (r.status == FindingStatus.OPEN || r.status == FindingStatus.REOPENED) {
                r.status = FindingStatus.RESOLVED;
                r.resolvedAt = now;
            }
            if (r.status == FindingStatus.RESOLVED) r.lastChecked = now;
        }
    }

    public FindingStatus statusFor(String host, String path, HeaderFinding f) {
        RetestRecord r = records.get(key(host, path, f));
        return r != null ? r.status : FindingStatus.OPEN;
    }

    public Optional<RetestRecord> recordFor(String host, String path, HeaderFinding f) {
        return Optional.ofNullable(records.get(key(host, path, f)));
    }

    /** For an aggregate (host-wide) finding: rollup across all its affected URLs. */
    public String aggregateStatusSummary(String host, List<String> affectedPaths, String issueName, String headerName) {
        int resolved = 0, reopened = 0, open = 0;
        for (String path : affectedPaths) {
            RetestRecord r = records.get(key(host, path, issueName, headerName));
            FindingStatus s = r != null ? r.status : FindingStatus.OPEN;
            switch (s) {
                case RESOLVED -> resolved++;
                case REOPENED -> reopened++;
                default -> open++;
            }
        }
        int total = affectedPaths.size();
        if (resolved == total) return "Resolved on all " + total + " URL(s)";
        if (reopened > 0) return reopened + "/" + total + " URL(s) reopened";
        if (resolved > 0) return resolved + "/" + total + " URL(s) resolved, " + open + " still open";
        return "Open on " + open + "/" + total + " URL(s)";
    }

    public void clear() { records.clear(); }
}
