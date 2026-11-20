package com.b3xal.headeranalyzer.scanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.b3xal.headeranalyzer.analyzer.HeaderAnalysisEngine;
import com.b3xal.headeranalyzer.model.HeaderFinding;
import com.b3xal.headeranalyzer.model.Severity;
import com.b3xal.headeranalyzer.model.UrlAnalysisResult;
import com.b3xal.headeranalyzer.util.SafeLogging;

import java.util.*;
import java.util.stream.Collectors;

import static burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue;

/** Publishes actionable credential/auth findings consistently from every analysis entry point. */
public final class NativeAuthIssuePublisher {
    private NativeAuthIssuePublisher() { }

    public static void publish(MontoyaApi api, UrlAnalysisResult result, HttpRequestResponse evidence,
                               String source) {
        String host = HeaderAnalysisEngine.extractHost(result.url);
        Map<String, List<HeaderFinding>> byNativeTitle = result.findings.stream()
                .filter(finding -> finding.category == HeaderFinding.Category.AUTH
                        && finding.severity != Severity.INFORMATION)
                .collect(Collectors.groupingBy(IssueFormatting::nativeTitle,
                        LinkedHashMap::new, Collectors.toList()));
        for (Map.Entry<String, List<HeaderFinding>> entry : byNativeTitle.entrySet()) {
            String nativeTitle = entry.getKey();
            List<HeaderFinding> findings = entry.getValue();
            HeaderFinding finding = findings.getFirst();
            if (!NativeIssueDeduplicator.first(host, nativeTitle)) continue;
            try {
                List<HttpRequestResponse> bases = result.probeExchanges.isEmpty()
                        ? List.of(evidence) : result.probeExchanges;
                List<HttpRequestResponse> issueEvidence = findings.stream()
                        .flatMap(each -> bases.stream().map(rr -> NativeEvidenceMarker.mark(rr, each)))
                        .toList();
                api.siteMap().add(auditIssue(
                        nativeTitle, findings.stream().map(each -> IssueFormatting.buildDetail(each, source))
                                .collect(Collectors.joining("<hr>")),
                        IssueFormatting.buildRemediation(finding), result.url,
                        finding.severity.burpSeverity, finding.confidence.burpConfidence,
                        "Detected by Quimera from " + source + ".",
                        null, finding.severity.burpSeverity, issueEvidence));
            } catch (Exception ex) {
                SafeLogging.error(api, "[Quimera] native auth issue error: " + ex.getMessage());
            }
        }
    }

    /** Publishes when the result retained its captured exchange; otherwise there is no safe
     * native issue evidence to attach. */
    public static void publishIfEvidencePresent(MontoyaApi api, UrlAnalysisResult result, String source) {
        if (result == null || result.originalRequest == null || result.originalResponse == null) return;
        publish(api, result, HttpRequestResponse.httpRequestResponse(result.originalRequest, result.originalResponse), source);
    }
}
