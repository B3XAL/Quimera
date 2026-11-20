package com.b3xal.headeranalyzer.ui;

import com.b3xal.headeranalyzer.config.QuimeraSettings;
import org.junit.jupiter.api.Test;

import javax.swing.SwingUtilities;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;

class HostFilterSynchronizationTest {

    @Test
    void mirroredHostUpdatesDoNotEchoIntermediateEmptyDocumentEvents() throws Exception {
        AtomicInteger headerCallbacks = new AtomicInteger();
        AtomicInteger cookieCallbacks = new AtomicInteger();
        SwingUtilities.invokeAndWait(() -> {
            var settings = new QuimeraSettings();
            var headers = new LoggerPanel(null, null, settings);
            var cookies = new CookiePanel(settings);
            headers.setOnHostFilterChanged(ignored -> headerCallbacks.incrementAndGet());
            cookies.setOnHostFilterChanged(ignored -> cookieCallbacks.incrementAndGet());

            headers.setSharedHostFilter("api.example.test");
            cookies.setSharedHostFilter("api.example.test");
            headers.setSharedHostFilter("");
            cookies.setSharedHostFilter("");
        });
        assertEquals(0, headerCallbacks.get());
        assertEquals(0, cookieCallbacks.get());
    }

    @Test
    void mirroredSearchUpdatesDoNotEchoIntermediateEmptyDocumentEvents() throws Exception {
        AtomicInteger headerCallbacks = new AtomicInteger();
        AtomicInteger cookieCallbacks = new AtomicInteger();
        SwingUtilities.invokeAndWait(() -> {
            var settings = new QuimeraSettings();
            var headers = new LoggerPanel(null, null, settings);
            var cookies = new CookiePanel(settings);
            headers.setOnSearchFilterChanged(ignored -> headerCallbacks.incrementAndGet());
            cookies.setOnSearchFilterChanged(ignored -> cookieCallbacks.incrementAndGet());

            headers.setSharedSearchFilter("refresh token");
            cookies.setSharedSearchFilter("refresh token");
            headers.setSharedSearchFilter("");
            cookies.setSharedSearchFilter("");
        });
        assertEquals(0, headerCallbacks.get());
        assertEquals(0, cookieCallbacks.get());
    }
}
