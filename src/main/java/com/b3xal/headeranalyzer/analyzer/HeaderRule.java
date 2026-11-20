package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.model.Confidence;
import com.b3xal.headeranalyzer.model.HeaderFinding.Category;
import com.b3xal.headeranalyzer.model.Severity;

import java.util.List;

public class HeaderRule {

    public final String headerName;

    // When mandatory header is absent
    public final boolean mandatory;
    public final String missingIssueName;
    public final String missingDescription;
    public final Severity missingSeverity;
    public final Confidence missingConfidence;
    public final Category missingCategory;

    // Checks applied when header IS present
    public final List<FieldCheck> checks;
    // Nullable, same contract as HeaderFinding.referenceUrl: a verified external writeup for the
    // "missing header" finding specifically, plumbed through by HeaderAnalysisEngine.
    public final String missingReferenceUrl;

    public HeaderRule(String headerName,
                      boolean mandatory,
                      String missingIssueName,
                      String missingDescription,
                      Severity missingSeverity,
                      Confidence missingConfidence,
                      Category missingCategory,
                      List<FieldCheck> checks) {
        this(headerName, mandatory, missingIssueName, missingDescription,
             missingSeverity, missingConfidence, missingCategory, checks, null);
    }

    public HeaderRule(String headerName,
                      boolean mandatory,
                      String missingIssueName,
                      String missingDescription,
                      Severity missingSeverity,
                      Confidence missingConfidence,
                      Category missingCategory,
                      List<FieldCheck> checks,
                      String missingReferenceUrl) {
        this.headerName        = headerName;
        this.mandatory         = mandatory;
        this.missingIssueName  = missingIssueName;
        this.missingDescription = missingDescription;
        this.missingSeverity   = missingSeverity;
        this.missingConfidence = missingConfidence;
        this.missingCategory   = missingCategory;
        this.checks            = List.copyOf(checks);
        this.missingReferenceUrl = missingReferenceUrl;
    }

    /** Mandatory header with both a missing-finding and value checks. */
    public HeaderRule(String headerName,
                      String missingIssueName,
                      String missingDescription,
                      Severity missingSeverity,
                      Confidence missingConfidence,
                      Category missingCategory,
                      List<FieldCheck> checks) {
        this(headerName, true, missingIssueName, missingDescription,
             missingSeverity, missingConfidence, missingCategory, checks, null);
    }

    /** Mandatory header with both a missing-finding and value checks, plus a reference link for
     * the missing-finding. */
    public HeaderRule(String headerName,
                      String missingIssueName,
                      String missingDescription,
                      Severity missingSeverity,
                      Confidence missingConfidence,
                      Category missingCategory,
                      List<FieldCheck> checks,
                      String missingReferenceUrl) {
        this(headerName, true, missingIssueName, missingDescription,
             missingSeverity, missingConfidence, missingCategory, checks, missingReferenceUrl);
    }

    /** Convenience: rule that only fires when header is absent (no value checks). */
    public HeaderRule(String headerName,
                      String missingIssueName,
                      String missingDescription,
                      Severity missingSeverity,
                      Confidence missingConfidence,
                      Category missingCategory) {
        this(headerName, true, missingIssueName, missingDescription,
             missingSeverity, missingConfidence, missingCategory, List.of(), null);
    }

    /** Convenience: rule with only value checks (not mandatory when absent). */
    public HeaderRule(String headerName, List<FieldCheck> checks) {
        this(headerName, false, null, null, null, null, null, checks, null);
    }
}
