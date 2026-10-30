package com.b3xal.headeranalyzer.config;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ExternalEvidenceArchiveSettingsTest {
    @Test
    void externalEvidenceArchiveIsDisabledUntilTheUserExplicitlyConfiguresIt() {
        QuimeraSettings settings = new QuimeraSettings();
        assertFalse(settings.isExternalEvidenceArchiveEnabled());
        assertEquals("", settings.getExternalEvidenceArchiveDirectory());

        settings.setExternalEvidenceArchive(true, "  /tmp/quimera-evidence  ");
        assertTrue(settings.isExternalEvidenceArchiveEnabled());
        assertEquals("/tmp/quimera-evidence", settings.getExternalEvidenceArchiveDirectory());

        settings.reset();
        assertFalse(settings.isExternalEvidenceArchiveEnabled());
        assertEquals("", settings.getExternalEvidenceArchiveDirectory());
    }
}
