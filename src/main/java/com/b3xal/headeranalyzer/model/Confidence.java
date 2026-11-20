package com.b3xal.headeranalyzer.model;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;

public enum Confidence {
    CERTAIN (0, "Certain",  AuditIssueConfidence.CERTAIN),
    FIRM    (1, "Firm",     AuditIssueConfidence.FIRM),
    TENTATIVE(2,"Tentative",AuditIssueConfidence.TENTATIVE);

    public final int order;
    public final String label;
    public final AuditIssueConfidence burpConfidence;

    Confidence(int order, String label, AuditIssueConfidence burpConfidence) {
        this.order          = order;
        this.label          = label;
        this.burpConfidence = burpConfidence;
    }
}
