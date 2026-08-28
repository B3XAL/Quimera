package com.b3xal.headeranalyzer.model;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

public class UrlAnalysisResult {

    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public final String url;
    public final String host;
    public final String path;
    public final List<HeaderFinding> findings;
    public final Map<String, String> rawHeaders;
    public final LocalDateTime timestamp;
    public final List<TechFinding> techFindings;

    /** Full raw HTTP request string (may be null if not captured). */
    public String rawRequest  = null;
    /** Full raw HTTP response string (may be null if not captured). */
    public String rawResponse = null;
    /** HTTP method of the request that produced this result (e.g. "GET"). Null if unknown. */
    public String method = null;
    /** HTTP status code of the response. -1 if unknown. */
    public int statusCode = -1;
    /** Response body length in bytes (matches Burp's own "Length" column). -1 if unknown. */
    public int contentLength = -1;
    /**
     * Non-null when this result came from an active probe (Active header scan) rather than
     * passive/proxy capture, e.g. "OPTIONS probe", "TRACE probe", "HSTS probe".
     */
    public String probeLabel = null;
    /**
     * The exact Montoya request object that produced this result, when available. Retest replays
     * this verbatim (same method/headers/body) rather than a generic fresh GET, so verification
     * happens "against the same query that detected the finding", not a different, looser check.
     */
    public HttpRequest originalRequest = null;
    /** The exact Montoya response object matching originalRequest, for Burp's native response editor. */
    public HttpResponse originalResponse = null;

    public UrlAnalysisResult(String url, String host, String path,
                              List<HeaderFinding> findings,
                              Map<String, String> rawHeaders) {
        this(url, host, path, findings, rawHeaders, List.of());
    }

    public UrlAnalysisResult(String url, String host, String path,
                              List<HeaderFinding> findings,
                              Map<String, String> rawHeaders,
                              List<TechFinding> techFindings) {
        this.url          = url;
        this.host         = host;
        this.path         = path;
        this.findings     = Collections.unmodifiableList(new ArrayList<>(findings));
        this.rawHeaders   = Collections.unmodifiableMap(new LinkedHashMap<>(rawHeaders));
        this.techFindings = Collections.unmodifiableList(new ArrayList<>(techFindings));
        this.timestamp    = LocalDateTime.now();
    }

    /** Returns a copy of this result with additional findings appended (used by ActiveHeaderScanner). */
    public UrlAnalysisResult withExtraFindings(List<HeaderFinding> extra) {
        List<HeaderFinding> merged = new ArrayList<>(findings);
        merged.addAll(extra);
        merged.sort(Comparator.comparingInt(f -> f.severity.order));
        UrlAnalysisResult copy = new UrlAnalysisResult(url, host, path, merged, rawHeaders, techFindings);
        copy.rawRequest  = this.rawRequest;
        copy.rawResponse = this.rawResponse;
        copy.method          = this.method;
        copy.statusCode      = this.statusCode;
        copy.contentLength   = this.contentLength;
        copy.probeLabel      = this.probeLabel;
        copy.originalRequest  = this.originalRequest;
        copy.originalResponse = this.originalResponse;
        return copy;
    }

    /** Returns a copy of this result with its findings list replaced wholesale (used when a
     * finding's severity is adjusted in place, e.g. PageSensitivity-driven escalation), as opposed
     * to {@link #withExtraFindings} which only appends. */
    public UrlAnalysisResult withReplacedFindings(List<HeaderFinding> replacement) {
        List<HeaderFinding> sorted = new ArrayList<>(replacement);
        sorted.sort(Comparator.comparingInt(f -> f.severity.order));
        UrlAnalysisResult copy = new UrlAnalysisResult(url, host, path, sorted, rawHeaders, techFindings);
        copy.rawRequest  = this.rawRequest;
        copy.rawResponse = this.rawResponse;
        copy.method            = this.method;
        copy.statusCode        = this.statusCode;
        copy.contentLength     = this.contentLength;
        copy.probeLabel        = this.probeLabel;
        copy.originalRequest   = this.originalRequest;
        copy.originalResponse  = this.originalResponse;
        return copy;
    }

    public Severity getWorstSeverity() {
        return findings.stream()
                .map(f -> f.severity)
                .min(Comparator.comparingInt(s -> s.order))
                .orElse(Severity.INFORMATION);
    }

    public String getTimestampStr() {
        return timestamp.format(FMT);
    }

    public long countBySeverity(Severity s) {
        return findings.stream().filter(f -> f.severity == s).count();
    }

    /**
     * Identity key used for in-place row storage (DomainData / Logger). Repeated passive GETs to
     * the same path collapse into one row (matches prior behaviour); active probes and non-GET
     * methods get their own row instead of silently overwriting the passive capture for that path.
     */
    public String rowKey() {
        StringBuilder sb = new StringBuilder(path);
        if (method != null && !method.equalsIgnoreCase("GET")) sb.append(" {").append(method).append('}');
        if (probeLabel != null) sb.append(" [").append(probeLabel).append(']');
        return sb.toString();
    }
}
