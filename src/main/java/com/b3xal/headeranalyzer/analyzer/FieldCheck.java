package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.model.Confidence;
import com.b3xal.headeranalyzer.model.HeaderFinding.Category;
import com.b3xal.headeranalyzer.model.Severity;

/** A single regex-based check with explicit severity, confidence and issue name. */
public class FieldCheck {

    public enum TriggerOn { MATCH, NO_MATCH }

    public final String regex;
    public final TriggerOn triggerOn;
    public final String issueName;
    public final String description;
    public final Severity severity;
    public final Confidence confidence;
    public final Category category;
    // Nullable, same contract as HeaderFinding.referenceUrl: a verified external writeup, only set
    // for the handful of checks worth a deeper read, plumbed through to the HeaderFinding this
    // check produces by HeaderAnalysisEngine.
    public final String referenceUrl;

    public FieldCheck(String regex, TriggerOn triggerOn,
                      String issueName, String description,
                      Severity severity, Confidence confidence,
                      Category category) {
        this(regex, triggerOn, issueName, description, severity, confidence, category, null);
    }

    public FieldCheck(String regex, TriggerOn triggerOn,
                      String issueName, String description,
                      Severity severity, Confidence confidence,
                      Category category, String referenceUrl) {
        this.regex       = regex;
        this.triggerOn   = triggerOn;
        this.issueName   = issueName;
        this.description = description;
        this.severity    = severity;
        this.confidence  = confidence;
        this.category    = category;
        this.referenceUrl = referenceUrl;
    }
}
