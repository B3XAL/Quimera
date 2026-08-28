package com.b3xal.headeranalyzer.model;

/**
 * A single security finding for one HTTP response header on one URL.
 */
public class HeaderFinding {

    public enum Category {
        SECURITY_MISSING,        // mandatory security header absent
        SECURITY_MISCONFIGURED,  // header present but wrongly configured
        INFORMATION_DISCLOSURE,  // header reveals server internals
        CSP,                     // Content-Security-Policy specific
        ADVISABLE,               // recommended but optional
        COOKIE,                  // Set-Cookie attribute findings
        CUSTOM,                  // user-defined rule (Rules tab)
        ACTIVE,                  // finding produced by an active probe (CORS reflection, TRACE, HSTS)
        AUTH,                    // JWT / Basic Auth / Bearer / API-key recognition (Cookies & Auth tab)
        STORAGE,                 // browser-bridge: PII/cache contents with no token identity (non-auth Web Storage/IndexedDB/CacheStorage)
        DOM                      // browser-bridge: rendered-DOM/postMessage/service-worker/runtime-CSP signals
    }

    public final String issueName;    // short title: "Missing Content Security Policy"
    public final String headerName;   // the HTTP header name
    public final String headerValue;  // null when header is absent
    public final String description;  // full explanation
    public final String evidence;     // POC / what was observed
    public final Severity severity;
    public final Confidence confidence;
    public final Category category;
    // Nullable, and deliberately rare: an external writeup/advisory URL for findings whose real
    // exploitability needs more than the description's paragraph to actually understand (a cache-
    // poisoning chain, a bypass technique with its own name), rendered as a "want to dig deeper?"
    // link in DetailPanel's Advisory pane. Most findings don't need one, the description already
    // says everything relevant, only set this for the handful worth a deeper read.
    public final String referenceUrl;

    public HeaderFinding(String issueName,
                         String headerName,
                         String headerValue,
                         String description,
                         String evidence,
                         Severity severity,
                         Confidence confidence,
                         Category category) {
        this(issueName, headerName, headerValue, description, evidence, severity, confidence, category, null);
    }

    public HeaderFinding(String issueName,
                         String headerName,
                         String headerValue,
                         String description,
                         String evidence,
                         Severity severity,
                         Confidence confidence,
                         Category category,
                         String referenceUrl) {
        this.issueName   = issueName;
        this.headerName  = headerName;
        this.headerValue = headerValue;
        this.description = description;
        this.evidence    = evidence;
        this.severity    = severity;
        this.confidence  = confidence;
        this.category    = category;
        this.referenceUrl = referenceUrl;
    }

    /** Key used for domain-level aggregation (same issue type across multiple URLs). */
    public String aggregationKey() {
        return issueName + "|" + headerName;
    }

    @Override
    public String toString() {
        return "[" + severity.label + "/" + confidence.label + "] " + issueName;
    }
}
