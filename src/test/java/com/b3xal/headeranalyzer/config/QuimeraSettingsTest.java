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
                        ToolType.PROXY.name(), ToolType.REPEATER.name(), ToolType.INTRUDER.name()),
                QuimeraSettings.DEFAULT_ENABLED_TOOLS);
        assertTrue(QuimeraSettings.DEFAULT_ENABLED_TOOLS.contains(ToolType.INTRUDER.name()));
        assertFalse(QuimeraSettings.DEFAULT_ENABLED_TOOLS.contains(ToolType.EXTENSIONS.name()));
    }

    @Test
    void restrictsAutomaticWorkToScopeByDefault() {
        assertTrue(new QuimeraSettings().isRestrictToScope());
    }

    @Test
    void automaticActiveProbesAreOptInByDefault() {
        QuimeraSettings settings = new QuimeraSettings();

        assertFalse(settings.isAutoActiveScan());
        assertTrue(settings.isActiveScanOptionsProbe());
        assertTrue(settings.isActiveScanTraceProbe());
        assertTrue(settings.isActiveScanHstsProbe());
        assertTrue(settings.isActiveScanWebDavProbe());
        assertTrue(settings.isJwtActiveProbeEnabled());
        assertTrue(settings.isSessionInvalidationProbeEnabled());
        assertTrue(settings.isGoogleApiKeyProbeEnabled());
        assertTrue(settings.isParameterInfluenceProbeEnabled());
    }

    @Test
    void enablingAutoActiveScanSelectsItsCoupledProbes() {
        QuimeraSettings settings = new QuimeraSettings();

        settings.setAutoActiveScan(false);
        settings.setJwtActiveProbeEnabled(false);
        settings.setSessionInvalidationProbeEnabled(false);
        settings.setGoogleApiKeyProbeEnabled(false);
        settings.setHeaderInfluenceProbeEnabled(false);
        settings.setCookieInfluenceProbeEnabled(false);
        settings.setParameterInfluenceProbeEnabled(false);

        settings.setAutoActiveScan(true);

        assertTrue(settings.isAutoActiveScan());
        assertTrue(settings.isJwtActiveProbeEnabled());
        assertTrue(settings.isSessionInvalidationProbeEnabled());
        assertTrue(settings.isGoogleApiKeyProbeEnabled());
        assertTrue(settings.isHeaderInfluenceProbeEnabled());
        assertTrue(settings.isCookieInfluenceProbeEnabled());
        assertTrue(settings.isParameterInfluenceProbeEnabled());
    }

    @Test
    void probesCanStillBeIndividuallyDisabledAfterEnablingAutoActiveScan() {
        QuimeraSettings settings = new QuimeraSettings();

        settings.setAutoActiveScan(true);
        settings.setJwtActiveProbeEnabled(false);
        settings.setSessionInvalidationProbeEnabled(false);
        settings.setGoogleApiKeyProbeEnabled(false);
        settings.setHeaderInfluenceProbeEnabled(false);
        settings.setCookieInfluenceProbeEnabled(false);
        settings.setParameterInfluenceProbeEnabled(false);

        assertTrue(settings.isAutoActiveScan());
        assertFalse(settings.isJwtActiveProbeEnabled());
        assertFalse(settings.isSessionInvalidationProbeEnabled());
        assertFalse(settings.isGoogleApiKeyProbeEnabled());
        assertFalse(settings.isHeaderInfluenceProbeEnabled());
        assertFalse(settings.isCookieInfluenceProbeEnabled());
        assertFalse(settings.isParameterInfluenceProbeEnabled());
    }

    @Test
    void resetRestoresScopeAndSafeAutoActiveDefaults() {
        QuimeraSettings settings = new QuimeraSettings();
        settings.setRestrictToScope(true);
        settings.setAutoActiveScan(false);
        settings.setActiveScanOptionsProbe(false);
        settings.setActiveScanTraceProbe(false);
        settings.setActiveScanHstsProbe(false);
        settings.setActiveScanWebDavProbe(false);
        settings.setJwtActiveProbeEnabled(false);
        settings.setSessionInvalidationProbeEnabled(false);
        settings.setGoogleApiKeyProbeEnabled(false);

        settings.reset();

        assertTrue(settings.isRestrictToScope());
        assertFalse(settings.isAutoActiveScan());
        assertTrue(settings.isActiveScanOptionsProbe());
        assertTrue(settings.isActiveScanTraceProbe());
        assertTrue(settings.isActiveScanHstsProbe());
        assertTrue(settings.isActiveScanWebDavProbe());
        assertTrue(settings.isJwtActiveProbeEnabled());
        assertTrue(settings.isSessionInvalidationProbeEnabled());
        assertTrue(settings.isGoogleApiKeyProbeEnabled());
    }
    @Test
    void headerInfluenceDefaultsBoundsAndReset() {
        QuimeraSettings settings = new QuimeraSettings();
        assertTrue(settings.isHeaderInfluenceProbeEnabled());
        assertEquals(333, settings.getHeaderInfluenceDelayMillis());
        assertTrue(settings.isParameterInfluenceProbeEnabled());
        settings.setHeaderInfluenceDelayMillis(-1);
        assertEquals(250, settings.getHeaderInfluenceDelayMillis());
        settings.setHeaderInfluenceDelayMillis(2000);
        assertEquals(2000, settings.getHeaderInfluenceDelayMillis());
        settings.setHeaderInfluenceProbeEnabled(false);
        settings.setParameterInfluenceProbeEnabled(false);
        settings.reset();
        assertTrue(settings.isHeaderInfluenceProbeEnabled());
        assertEquals(333, settings.getHeaderInfluenceDelayMillis());
        assertTrue(settings.isParameterInfluenceProbeEnabled());
    }

    @Test
    void probesCanBeDisabledAfterAutoActiveScanIsEnabled() {
        // Contract (see QuimeraSettings#setAutoActiveScan): turning Auto Active Scan on selects
        // every active probe; each one remains independently configurable afterwards, and opting
        // one out does not get re-forced on until Auto Active Scan is toggled on again.
        QuimeraSettings settings = new QuimeraSettings();
        settings.setAutoActiveScan(true);
        assertTrue(settings.isHeaderInfluenceProbeEnabled());
        assertTrue(settings.isCookieInfluenceProbeEnabled());
        settings.setHeaderInfluenceProbeEnabled(false);
        assertFalse(settings.isHeaderInfluenceProbeEnabled());
        // Disabling a single probe does not disturb Auto Active Scan or the other probes.
        assertTrue(settings.isAutoActiveScan());
        assertTrue(settings.isCookieInfluenceProbeEnabled());
    }

}
