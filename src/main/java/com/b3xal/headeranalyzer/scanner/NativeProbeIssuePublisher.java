package com.b3xal.headeranalyzer.scanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.b3xal.headeranalyzer.model.Confidence;
import com.b3xal.headeranalyzer.model.HeaderFinding;
import com.b3xal.headeranalyzer.model.UrlAnalysisResult;
import com.b3xal.headeranalyzer.util.SafeLogging;

import java.util.List;
import java.net.URI;

import static burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue;

/** Publishes CONFIRMED findings from Quimera's own active probes (cache-key disclosure, CORS
 * reflection, TRACE, HSTS) to Burp's native Issues tab, from whichever caller produced the probe
 * result: the auto-active-scan listener (QuimeraHttpHandler) or the manual "Active scan" context
 * menu action (ContextMenuProvider). Unlike ordinary passive findings, an active probe result
 * (result.probeLabel != null, backed by result.probeExchanges) already required Quimera to send
 * real diagnostic traffic and observe a real response, the opposite of the "every passive header
 * read is noise" reasoning that keeps ordinary INFORMATION_DISCLOSURE findings out of native
 * Issues. Confidence.CERTAIN only, so a TENTATIVE probe result never reaches Issues. */
public final class NativeProbeIssuePublisher {
    private NativeProbeIssuePublisher() {}

    public static void publish(MontoyaApi api, UrlAnalysisResult result) {
        if (result.probeLabel == null || result.probeExchanges.isEmpty()) return;
        String affectedUrl = affectedUrl(result);
        for (HeaderFinding finding : result.findings) {
            if (finding.confidence != Confidence.CERTAIN) continue;
            String nativeTitle = IssueFormatting.nativeTitle(finding);
            // A DISTINCT dedup key from HeaderPassiveScanner's/publishNativeAuthIssues' plain
            // host::title one. Both publishers share one static NativeIssueDeduplicator, and the
            // passive scan check fires synchronously on ordinary traffic, so it can (and does, in
            // practice) claim "host::title" first with weak/incidental evidence, e.g. the one
            // endpoint that happens to disclose a cache key on completely unmodified traffic,
            // before this probe (several sequential requests, always slower) gets a chance to
            // publish its OWN, actively-verified 200-status evidence for a DIFFERENT URL under the
            // exact same title. Sharing the key meant the probe's real finding was silently
            // dropped every time, "first writer wins" arbitrarily favouring speed over quality.
            //
            // Keyed by the full URL, not just the host: an active probe (cache-key disclosure,
            // CORS reflection, TRACE, HSTS) can legitimately fire on many distinct endpoints of
            // the same host, each with its own actively-verified evidence. A host-only key was
            // collapsing every URL after the first one under the same finding title into a single
            // dropped duplicate, e.g. a cache-key probe that logged "disclosure=true" for ten
            // different URLs but only ever surfaced one native Issue.
            if (!NativeIssueDeduplicator.first(affectedUrl, "active-probe::" + nativeTitle)) continue;
            try {
                List<HttpRequestResponse> issueEvidence = result.probeExchanges.stream()
                        .map(rr -> NativeEvidenceMarker.mark(rr, finding)).toList();
                api.siteMap().add(auditIssue(
                        nativeTitle, IssueFormatting.buildDetail(finding, IssueFormatting.SOURCE_HTTP),
                        IssueFormatting.buildRemediation(finding), affectedUrl,
                        finding.severity.burpSeverity, finding.confidence.burpConfidence,
                        "Detected by Quimera's active " + result.probeLabel + ".",
                        null, finding.severity.burpSeverity, issueEvidence));
            } catch (Exception ex) {
                SafeLogging.error(api, "[Quimera] native probe issue error: " + ex.getMessage());
            }
        }
    }

    /** UrlAnalysisResult.url is normalized without its query string for historical reporting,
     * while path now carries the real path+query row identity. Recompose both here: cache keys
     * are query-sensitive and /post?id=1 and /post?id=2 must become distinct native issues. */
    static String affectedUrl(UrlAnalysisResult result) {
        try {
            URI base = URI.create(result.url);
            int queryAt = result.path.indexOf('?');
            String path = queryAt < 0 ? result.path : result.path.substring(0, queryAt);
            String query = queryAt < 0 ? null : result.path.substring(queryAt + 1);
            return new URI(base.getScheme(), base.getUserInfo(), base.getHost(), base.getPort(),
                    path, query, null).toString();
        } catch (Exception ignored) {
            return result.url + "|" + result.path;
        }
    }
}
