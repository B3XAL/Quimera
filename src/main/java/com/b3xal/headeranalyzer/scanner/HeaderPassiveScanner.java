package com.b3xal.headeranalyzer.scanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.scancheck.PassiveScanCheck;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.b3xal.headeranalyzer.analyzer.HeaderAnalysisEngine;
import com.b3xal.headeranalyzer.analyzer.JwtActiveProbe;
import com.b3xal.headeranalyzer.analyzer.GoogleApiKeyProbe;
import com.b3xal.headeranalyzer.config.QuimeraSettings;
import com.b3xal.headeranalyzer.model.HeaderFinding;
import com.b3xal.headeranalyzer.model.Severity;
import com.b3xal.headeranalyzer.model.UrlAnalysisResult;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static burp.api.montoya.scanner.AuditResult.auditResult;
import static burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue;

public class HeaderPassiveScanner implements PassiveScanCheck {

    private final MontoyaApi api;
    private final HeaderAnalysisEngine engine;
    private final QuimeraSettings settings;
    // host::issueName already raised, prevents duplicate Issues across URLs of the same host

    /**
     * Note: this check only feeds Burp's native Issues tab (AuditIssue). Populating Quimera's own
     * Logger is handled uniformly for every tool by {@link com.b3xal.headeranalyzer.proxy.QuimeraHttpHandler},
     * so this class deliberately does not touch the UI, doing so as well would double-count results.
     */
    public HeaderPassiveScanner(MontoyaApi api,
                                HeaderAnalysisEngine engine,
                                QuimeraSettings settings) {
        this.api      = api;
        this.engine   = engine;
        this.settings = settings;
    }

    @Override
    public String checkName() {
        return "Quimera \u2013 HTTP Header Security";
    }

    @Override
    public AuditResult doCheck(HttpRequestResponse baseRequestResponse) {
        if (baseRequestResponse.response() == null) return auditResult(List.of());

        // JwtActiveProbe's own control/forged-token requests (see that header's own javadoc):
        // Burp's Scanner invokes this check on ALL traffic independently of QuimeraHttpHandler's
        // own EXTENSIONS-tagged-traffic handling, so that class's marker-header guard doesn't
        // cover this second, separate passive-analysis entry point. Without this, JwtActiveProbe's
        // fixed garbage control token (never issued by the target, purely internal comparison
        // material) kept raising a genuine-looking native Burp Issue about Quimera's own synthetic
        // data.
        if (baseRequestResponse.request().hasHeader(JwtActiveProbe.MARKER_HEADER)
                || baseRequestResponse.request().hasHeader(GoogleApiKeyProbe.MARKER_HEADER)
                || JwtActiveProbe.carriesGarbageToken(baseRequestResponse.request())) return auditResult(List.of());

        String url = baseRequestResponse.request().url();
        if (HeaderAnalysisEngine.isOutOfBandProbeUrl(url)
                || HeaderAnalysisEngine.isQuimeraInternalUrl(url)) return auditResult(List.of());

        // Collect response headers (merge multiple Set-Cookie values)
        Map<String, String> headerMap = new LinkedHashMap<>();
        baseRequestResponse.response().headers().forEach(h ->
                com.b3xal.headeranalyzer.util.HeaderMaps.addResponse(headerMap, h.name(), h.value()));

        // Skip static/binary assets, no value in checking security headers on images etc.
        String contentType = headerMap.getOrDefault("Content-Type",
                             headerMap.getOrDefault("content-type", ""));
        if (!settings.shouldAnalyze(contentType, url)) return auditResult(List.of());

        // Analyze headers with context-aware filtering
        UrlAnalysisResult result = engine.analyze(url, headerMap,
                baseRequestResponse.response().statusCode(), baseRequestResponse.response().bodyToString(),
                baseRequestResponse.request().method());

        // Capture raw HTTP message for the issue detail viewer
        try {
            result.rawRequest  = baseRequestResponse.request().toString();
            result.rawResponse = baseRequestResponse.response().toString();
        } catch (Exception ignored) {}

        // Build Scanner issues for HIGH/MEDIUM/LOW (any confidence, CERTAIN/FIRM/TENTATIVE are
        // already carried onto the native AuditIssue itself and Burp's own Issue Activity view
        // filters/sorts by them). INFORMATION severity is deliberately EXCLUDED from Burp's native
        // Issues tab: it's the "no exploitable vector beyond default probing" tier (Via, X-Cache,
        // Server-Timing, ...), real signal for an analyst working inside Quimera's own curated
        // tabs (which still show every severity, unfiltered), but pure noise once mixed into
        // Burp's shared Issues tab alongside every other extension/Scanner's findings. Cookies
        // consolidated by type. Each issue is reported at most once per host (dedup by
        // host::issueName).
        List<AuditIssue> issues = new ArrayList<>();
        String host = HeaderAnalysisEngine.extractHost(url);

        // Separate cookie findings from the rest
        List<HeaderFinding> cookieFindings = new ArrayList<>();
        for (HeaderFinding finding : result.findings) {
            if (finding.severity == Severity.INFORMATION) continue;
            if (finding.category == HeaderFinding.Category.COOKIE) {
                cookieFindings.add(finding);
            } else {
                String nativeTitle = IssueFormatting.nativeTitle(finding);
                if (!NativeIssueDeduplicator.first(host, nativeTitle)) continue;
                try {
                    // Was gated on finding.headerValue != null, meant as a proxy for "is the
                    // header actually present" (nothing to highlight for a missing header), but
                    // CspAnalyzer's deep-CSP findings always carry a null headerValue by
                    // construction (they analyze the whole policy string, not a single value)
                    // even though the CSP header IS present, so every CSP finding silently never
                    // got highlighted in the Issues tab. withResponseHighlight already no-ops
                    // safely when the header isn't in the response (empty marker list), so it's
                    // correct to just always attempt it instead of pre-guessing from headerValue.
                    HttpRequestResponse markedRr = NativeEvidenceMarker.mark(baseRequestResponse, finding);
                    issues.add(auditIssue(
                            nativeTitle,
                            IssueFormatting.buildDetail(finding, IssueFormatting.SOURCE_HTTP),
                            IssueFormatting.buildRemediation(finding),
                            url,
                            finding.severity.burpSeverity,
                            finding.confidence.burpConfidence,
                            "Detected by the Quimera header security extension.",
                            null,
                            finding.severity.burpSeverity,
                            markedRr
                    ));
                } catch (Exception ex) {
                    api.logging().logToError("[Quimera] auditIssue error: " + ex.getMessage());
                }
            }
        }

        // Consolidate cookie findings: group by simplified issue type (already LOW+ only, the
        // INFORMATION-severity ones were filtered out of cookieFindings above)
        if (!cookieFindings.isEmpty()) {
            Map<String, List<HeaderFinding>> byCookieType = new LinkedHashMap<>();
            for (HeaderFinding cf : cookieFindings) {
                String key = IssueFormatting.simplifyIssue(cf.issueName);
                byCookieType.computeIfAbsent(key, k -> new ArrayList<>()).add(cf);
            }
            for (Map.Entry<String, List<HeaderFinding>> entry : byCookieType.entrySet()) {
                HeaderFinding representative = entry.getValue().get(0);
                String nativeTitle = IssueFormatting.nativeTitle(new HeaderFinding(
                        entry.getKey(), representative.headerName, representative.headerValue,
                        representative.description, representative.evidence, representative.severity,
                        representative.confidence, representative.category, representative.referenceUrl));
                if (!NativeIssueDeduplicator.first(host, nativeTitle)) continue;
                String cookieNames = entry.getValue().stream()
                        .map(f -> f.headerValue != null ? f.headerValue.split(";")[0].trim() : "?")
                        .distinct()
                        .reduce((a, b) -> a + ", " + b)
                        .orElse("unknown");
                String detail = IssueFormatting.buildDetail(representative, IssueFormatting.SOURCE_HTTP) +
                        "<br><b>Affected cookies:</b> <code>" + IssueFormatting.escHtml(cookieNames) + "</code>";
                try {
                    // For cookie findings, highlight all Set-Cookie lines in the response
                    HttpRequestResponse markedRr = NativeEvidenceMarker.mark(baseRequestResponse, representative);
                    issues.add(auditIssue(
                            nativeTitle,
                            detail,
                            IssueFormatting.buildRemediation(representative),
                            url,
                            representative.severity.burpSeverity,
                            representative.confidence.burpConfidence,
                            "Detected by the Quimera header security extension.",
                            null,
                            representative.severity.burpSeverity,
                            markedRr
                    ));
                } catch (Exception ex) {
                    api.logging().logToError("[Quimera] auditIssue error: " + ex.getMessage());
                }
            }
        }

        return auditResult(issues);
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue newIssue, AuditIssue existingIssue) {
        // Cache-key and other endpoint-specific findings can share a title across many URLs.
        // Consolidating on name alone made the first issue (often /academyLabHeader returning
        // 404) suppress every later 200 finding on the host. Only the same title at the exact
        // same URL is a duplicate.
        return sameIssueInstance(newIssue.name(), newIssue.baseUrl(),
                existingIssue.name(), existingIssue.baseUrl())
                ? ConsolidationAction.KEEP_EXISTING
                : ConsolidationAction.KEEP_BOTH;
    }

    static boolean sameIssueInstance(String newName, String newUrl,
                                     String existingName, String existingUrl) {
        return java.util.Objects.equals(newName, existingName)
                && java.util.Objects.equals(newUrl, existingUrl);
    }

    // ------ Filtering helpers ---------------------------------------------------------------------------------------------------------------------------------------------------------------
    // simplifyIssue/buildDetail/buildRemediation/escHtml moved to IssueFormatting so the browser-
    // bridge issue reporter (com.b3xal.headeranalyzer.browser.BrowserIssueReporter) formats and
    // remediates the exact same way, one finding, one format, regardless of source.

}
