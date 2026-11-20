package com.b3xal.headeranalyzer.model;

/** Verification state of a tracked finding, layered on top of the live analysis results. */
public enum FindingStatus {
    OPEN("Open"),
    RESOLVED("Resolved"),
    /** Was RESOLVED, then observed present again on a later analysis/retest. */
    REOPENED("Reopened");

    public final String label;
    FindingStatus(String label) { this.label = label; }
}
