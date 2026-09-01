package com.b3xal.headeranalyzer.config;

import burp.api.montoya.core.ToolType;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class QuimeraSettingsTest {

    @Test
    void freshInstallUsesOnlyRequestedPassiveTools() {
        assertEquals(Set.of(ToolType.SCANNER.name(), ToolType.TARGET.name(), ToolType.BURP_AI.name(),
                        ToolType.PROXY.name(), ToolType.REPEATER.name()),
                QuimeraSettings.DEFAULT_ENABLED_TOOLS);
        assertFalse(QuimeraSettings.DEFAULT_ENABLED_TOOLS.contains(ToolType.INTRUDER.name()));
        assertFalse(QuimeraSettings.DEFAULT_ENABLED_TOOLS.contains(ToolType.EXTENSIONS.name()));
    }

    @Test
    void analyzesAllTrafficByDefault() {
        assertFalse(new QuimeraSettings().isRestrictToScope());
    }

    @Test
    void autoActiveScanAndEveryIndividualProbeAreEnabledByDefault() {
        QuimeraSettings settings = new QuimeraSettings();

        assertTrue(settings.isAutoActiveScan());
        assertTrue(settings.isActiveScanOptionsProbe());
        assertTrue(settings.isActiveScanTraceProbe());
        assertTrue(settings.isActiveScanHstsProbe());
        assertTrue(settings.isJwtActiveProbeEnabled());
        assertTrue(settings.isSessionInvalidationProbeEnabled());
        assertTrue(settings.isGoogleApiKeyProbeEnabled());
    }

    @Test
    void enablingAutoActiveScanSelectsItsCoupledProbes() {
        QuimeraSettings settings = new QuimeraSettings();

        settings.setAutoActiveScan(false);
        settings.setJwtActiveProbeEnabled(false);
        settings.setSessionInvalidationProbeEnabled(false);
        settings.setGoogleApiKeyProbeEnabled(false);

        settings.setAutoActiveScan(true);

        assertTrue(settings.isAutoActiveScan());
        assertTrue(settings.isJwtActiveProbeEnabled());
        assertTrue(settings.isSessionInvalidationProbeEnabled());
        assertTrue(settings.isGoogleApiKeyProbeEnabled());
    }

    @Test
    void probesCanStillBeIndividuallyDisabledAfterEnablingAutoActiveScan() {
        QuimeraSettings settings = new QuimeraSettings();

        settings.setJwtActiveProbeEnabled(false);
        settings.setSessionInvalidationProbeEnabled(false);
        settings.setGoogleApiKeyProbeEnabled(false);

        assertTrue(settings.isAutoActiveScan());
        assertFalse(settings.isJwtActiveProbeEnabled());
        assertFalse(settings.isSessionInvalidationProbeEnabled());
        assertFalse(settings.isGoogleApiKeyProbeEnabled());
    }

    @Test
    void resetRestoresAnalyzeAllAndAllAutoActiveDefaults() {
        QuimeraSettings settings = new QuimeraSettings();
        settings.setRestrictToScope(true);
        settings.setAutoActiveScan(false);
        settings.setActiveScanOptionsProbe(false);
        settings.setActiveScanTraceProbe(false);
        settings.setActiveScanHstsProbe(false);
        settings.setJwtActiveProbeEnabled(false);
        settings.setSessionInvalidationProbeEnabled(false);
        settings.setGoogleApiKeyProbeEnabled(false);

        settings.reset();

        assertFalse(settings.isRestrictToScope());
        assertTrue(settings.isAutoActiveScan());
        assertTrue(settings.isActiveScanOptionsProbe());
        assertTrue(settings.isActiveScanTraceProbe());
        assertTrue(settings.isActiveScanHstsProbe());
        assertTrue(settings.isJwtActiveProbeEnabled());
        assertTrue(settings.isSessionInvalidationProbeEnabled());
        assertTrue(settings.isGoogleApiKeyProbeEnabled());
    }
}
