package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.model.HeaderFinding;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class ReferrerPolicyContextTest {

    @Test
    void absentInvalidAndSafePoliciesAreNotFindings() {
        assertNull(HeaderAnalysisEngine.analyzeReferrerPolicy(null));
        assertNull(HeaderAnalysisEngine.analyzeReferrerPolicy("not-a-policy"));
        assertNull(HeaderAnalysisEngine.analyzeReferrerPolicy("strict-origin-when-cross-origin"));
        assertNull(HeaderAnalysisEngine.analyzeReferrerPolicy("unsafe-url, no-referrer"));
    }

    @Test
    void lastRecognisedFallbackTokenDeterminesEffectiveUnsafePolicy() {
        HeaderFinding unsafe = HeaderAnalysisEngine.analyzeReferrerPolicy(
                "strict-origin-when-cross-origin, unsafe-url, future-policy");
        assertEquals("Referrer-Policy set to unsafe-url", unsafe.issueName);

        HeaderFinding legacy = HeaderAnalysisEngine.analyzeReferrerPolicy(
                "no-referrer, no-referrer-when-downgrade");
        assertEquals("Referrer-Policy exposes full URLs cross-origin", legacy.issueName);
    }

    @Test
    void recognisedSafeTokenAfterUnknownTokenRemainsSafe() {
        assertNull(HeaderAnalysisEngine.analyzeReferrerPolicy(
                "unsafe-url, future-policy, strict-origin"));
    }
}
