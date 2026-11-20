package com.b3xal.headeranalyzer.ui;

import com.b3xal.headeranalyzer.model.Confidence;
import com.b3xal.headeranalyzer.model.HeaderFinding;
import com.b3xal.headeranalyzer.model.Severity;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

class LoggerPanelGroupingTest {

    @Test
    void keepsContextualSeveritiesInSeparateIssueRows() {
        HeaderFinding informational = finding(Severity.INFORMATION);
        HeaderFinding medium = finding(Severity.MEDIUM);

        assertNotEquals(LoggerPanel.issueGroupKey(informational), LoggerPanel.issueGroupKey(medium));
        assertEquals(LoggerPanel.issueGroupKey(informational),
                LoggerPanel.issueGroupKey(finding(Severity.INFORMATION)));
    }

    private static HeaderFinding finding(Severity severity) {
        return new HeaderFinding("Missing HTTP Strict Transport Security", "Strict-Transport-Security",
                null, "description", "evidence", severity, Confidence.CERTAIN,
                HeaderFinding.Category.SECURITY_MISSING);
    }
}
