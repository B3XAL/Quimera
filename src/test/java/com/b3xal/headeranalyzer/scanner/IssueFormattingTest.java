package com.b3xal.headeranalyzer.scanner;

import com.b3xal.headeranalyzer.model.Confidence;
import com.b3xal.headeranalyzer.model.HeaderFinding;
import com.b3xal.headeranalyzer.model.Severity;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

class IssueFormattingTest {

    @Test
    void nativeDetailAlwaysIdentifiesExtensionAndSource() {
        HeaderFinding finding = new HeaderFinding(
                "Missing HSTS", "Strict-Transport-Security", null,
                "The header is absent.", "Header not present",
                Severity.MEDIUM, Confidence.CERTAIN, HeaderFinding.Category.SECURITY_MISSING);

        String detail = IssueFormatting.buildDetail(finding, IssueFormatting.SOURCE_HTTP);

        assertTrue(detail.startsWith("<b>Extension:</b> Quimera<br>"));
        assertTrue(detail.contains("<b>Source:</b> Passive HTTP analysis<br>"));
    }

    @Test
    void sourceIsEscapedBeforeAddingItToNativeIssueHtml() {
        HeaderFinding finding = new HeaderFinding(
                "Test", "X-Test", "value", "Description", "Evidence",
                Severity.LOW, Confidence.FIRM, HeaderFinding.Category.CUSTOM);

        String detail = IssueFormatting.buildDetail(finding, "Browser <bridge>");

        assertTrue(detail.contains("<b>Source:</b> Browser &lt;bridge&gt;<br>"));
    }
}
