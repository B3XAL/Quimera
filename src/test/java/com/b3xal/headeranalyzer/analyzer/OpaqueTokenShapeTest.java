package com.b3xal.headeranalyzer.analyzer;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OpaqueTokenShapeTest {

    @Test
    void rejectsAbsoluteAndRelativeApplicationRoutes() {
        assertFalse(WebStorageAnalyzer.looksLikeOpaqueToken("/Account/ResetPassword"));
        assertFalse(WebStorageAnalyzer.looksLikeOpaqueToken("users/unlock-user"));
        assertFalse(WebStorageAnalyzer.looksLikeOpaqueToken("account/reset/password"));
    }

    @Test
    void retainsOpaqueCredentialShapes() {
        assertTrue(WebStorageAnalyzer.looksLikeOpaqueToken("abcDEF0123456789_xyz"));
        assertTrue(WebStorageAnalyzer.looksLikeOpaqueToken("YWJjZGVmZ2hpL2tsbW5vcA=="));
    }
}
