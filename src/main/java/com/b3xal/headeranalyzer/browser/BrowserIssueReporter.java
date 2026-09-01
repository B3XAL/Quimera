package com.b3xal.headeranalyzer.browser;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.b3xal.headeranalyzer.model.HeaderFinding;
import com.b3xal.headeranalyzer.model.Severity;
import com.b3xal.headeranalyzer.scanner.IssueFormatting;
import com.b3xal.headeranalyzer.scanner.NativeEvidenceMarker;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import static burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue;

/**
 * Raises browser-bridge findings into Burp's native Issues tab ({@code api.siteMap().add(...)}),
 * so a vulnerability shows up there the exact same way regardless of whether it came from HTTP
 * traffic ({@link com.b3xal.headeranalyzer.scanner.HeaderPassiveScanner}) or the browser extension.
 * Same {@link IssueFormatting} detail/remediation text, same cookie-consolidation rule, same
 * dedup-by-host-and-issue-name behaviour as the HTTP-driven path.
 *
 * A browser-bridge finding has no real HTTP transaction behind it (Web Storage, cookies, DOM
 * signals aren't HTTP responses), but {@code AuditIssue} still needs an {@code HttpRequestResponse}
 * as evidence for Burp's Issue viewer to render. {@link BrowserEvidence} builds that (a request for
 * the real page URL, a synthetic response whose body is the actual collected payload), the SAME
 * evidence object {@code BrowserBridgeServer} also sets on the plain Headers/Cookies &amp; Auth
 * logger's request/response viewer panes, one synthetic response, every consumer sees the same one.
 */
public final class BrowserIssueReporter {

    private final MontoyaApi api;
    // host::issueName already raised, matches HeaderPassiveScanner's own dedup key shape, kept in
    // a SEPARATE set (not shared with HeaderPassiveScanner's) since the two report through
    // different pipelines and a browser-only finding (e.g. "Session cookie confirmed JS-readable")
    // has no HTTP-side equivalent to accidentally collide with anyway.
    private final Set<String> reportedIssueKeys = ConcurrentHashMap.newKeySet();

    public BrowserIssueReporter(MontoyaApi api) {
        this.api = api;
    }

    /**
     * @param url      the page URL the findings were collected from.
     * @param host     the page's host, used for the dedup key.
     * @param payload  the collected snapshot, forwarded to {@link BrowserEvidence#build} so the
     *                 Issue viewer's response pane shows the actual data, not just finding titles.
     * @param findings findings already produced by {@link BrowserStorageAnalyzer}/{@link BrowserDomAnalyzer}.
     */
    public void report(String url, String host, BrowserPayload payload, List<HeaderFinding> findings) {
        if (findings == null || findings.isEmpty()) return;
        HttpRequestResponse evidence = BrowserEvidence.build(payload);

        List<HeaderFinding> cookieFindings = new ArrayList<>();
        for (HeaderFinding f : findings) {
            // Same rule as HeaderPassiveScanner: INFORMATION severity stays inside Quimera's own
            // curated tabs, only LOW+ goes into Burp's shared Issues tab.
            if (f.severity == Severity.INFORMATION) continue;
            if (f.category == HeaderFinding.Category.COOKIE) {
                cookieFindings.add(f);
                continue;
            }
            String nativeTitle = IssueFormatting.nativeTitle(f);
            String issueKey = host + "::" + nativeTitle;
            if (!reportedIssueKeys.add(issueKey)) continue;
            addIssue(nativeTitle, IssueFormatting.buildDetail(f, IssueFormatting.SOURCE_BROWSER),
                    IssueFormatting.buildRemediation(f), url, f, evidence);
        }

        // Same consolidation HeaderPassiveScanner applies: every per-cookie finding of the same
        // simplified type becomes one Issues-tab entry instead of one per cookie name.
        if (!cookieFindings.isEmpty()) {
            Map<String, List<HeaderFinding>> byType = new LinkedHashMap<>();
            for (HeaderFinding cf : cookieFindings) {
                byType.computeIfAbsent(IssueFormatting.simplifyIssue(cf.issueName), k -> new ArrayList<>()).add(cf);
            }
            for (Map.Entry<String, List<HeaderFinding>> entry : byType.entrySet()) {
                HeaderFinding representative = entry.getValue().get(0);
                String nativeTitle = IssueFormatting.nativeTitle(new HeaderFinding(
                        entry.getKey(), representative.headerName, representative.headerValue,
                        representative.description, representative.evidence, representative.severity,
                        representative.confidence, representative.category, representative.referenceUrl));
                String issueKey = host + "::" + nativeTitle;
                if (!reportedIssueKeys.add(issueKey)) continue;
                addIssue(nativeTitle, IssueFormatting.buildDetail(representative, IssueFormatting.SOURCE_BROWSER),
                        IssueFormatting.buildRemediation(representative), url, representative, evidence);
            }
        }
    }

    private void addIssue(String name, String detail, String remediation, String url,
                           HeaderFinding f, HttpRequestResponse evidence) {
        try {
            api.siteMap().add(auditIssue(
                    name, detail, remediation, url,
                    f.severity.burpSeverity, f.confidence.burpConfidence,
                    "Detected by the Quimera browser extension bridge (Web Storage, cookies, rendered DOM, postMessage listeners).",
                    null, f.severity.burpSeverity, NativeEvidenceMarker.mark(evidence, f)));
        } catch (Exception ex) {
            api.logging().logToError("[Quimera] browser bridge auditIssue error: " + ex.getMessage());
        }
    }
}
