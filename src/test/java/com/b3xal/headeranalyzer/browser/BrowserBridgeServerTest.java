package com.b3xal.headeranalyzer.browser;

import burp.api.montoya.MontoyaApi;
import com.b3xal.headeranalyzer.analyzer.HeaderAnalysisEngine;
import com.b3xal.headeranalyzer.analyzer.RuleStore;
import com.b3xal.headeranalyzer.config.QuimeraSettings;
import com.b3xal.headeranalyzer.util.JsonUtil;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BrowserBridgeServerTest {

    @Test
    void acceptsSchemaVersionOneAsParsedFromJson() {
        Object parsed = ((Map<?, ?>) JsonUtil.parse("{\"schemaVersion\":1}"))
                .get("schemaVersion");

        assertTrue(BrowserBridgeServer.isSupportedSchemaVersion(parsed));
    }

    @Test
    void acceptsCompatibleRepresentationsAndRejectsOtherVersions() {
        assertTrue(BrowserBridgeServer.isSupportedSchemaVersion(1));
        assertTrue(BrowserBridgeServer.isSupportedSchemaVersion(1L));
        assertTrue(BrowserBridgeServer.isSupportedSchemaVersion("1"));

        assertFalse(BrowserBridgeServer.isSupportedSchemaVersion(null));
        assertFalse(BrowserBridgeServer.isSupportedSchemaVersion(1.1));
        assertFalse(BrowserBridgeServer.isSupportedSchemaVersion(2));
        assertFalse(BrowserBridgeServer.isSupportedSchemaVersion("2"));
    }

    @Test
    void ingestStillRunsWithScopeRestrictionEnabledAndNoBurpScope() throws Exception {
        int port;
        try (ServerSocket candidate = new ServerSocket(0)) {
            port = candidate.getLocalPort();
        }
        QuimeraSettings settings = new QuimeraSettings();
        settings.setBrowserBridgeEnabled(true);
        settings.setBrowserBridgePort(port);
        settings.setBrowserBridgeToken("a".repeat(43));
        settings.setRestrictToScope(true); // legacy/display setting must never gate ingest
        HeaderAnalysisEngine engine = new HeaderAnalysisEngine(new RuleStore(null), settings);
        CountDownLatch received = new CountDownLatch(1);
        BrowserBridgeServer server = new BrowserBridgeServer(
                loggingOnlyApi(), settings, engine, result -> received.countDown());
        server.start();
        try {
            String body = """
                    {"payload":{"schemaVersion":1,"href":"https://outside-scope.test/path",
                    "origin":"https://outside-scope.test","host":"outside-scope.test",
                    "path":"/path","localStorage":{},"sessionStorage":{},"dom":{}},
                    "localFindings":[]}
                    """;
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("http://127.0.0.1:" + port + "/quimera/v1/ingest"))
                    .timeout(Duration.ofSeconds(5))
                    .header("Origin", "chrome-extension://integration-test")
                    .header("Content-Type", "application/json")
                    .header("X-Quimera-Token", "a".repeat(43))
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();
            HttpResponse<String> response = HttpClient.newHttpClient().send(
                    request, HttpResponse.BodyHandlers.ofString());

            assertEquals(200, response.statusCode());
            assertTrue(received.await(2, TimeUnit.SECONDS));
            assertFalse(response.body().contains("outside_burp_target_scope"));
        } finally {
            server.shutdown();
        }
    }

    private static MontoyaApi loggingOnlyApi() {
        Object logging = Proxy.newProxyInstance(
                BrowserBridgeServerTest.class.getClassLoader(),
                new Class<?>[]{burp.api.montoya.logging.Logging.class},
                (proxy, method, args) -> null);
        return (MontoyaApi) Proxy.newProxyInstance(
                BrowserBridgeServerTest.class.getClassLoader(),
                new Class<?>[]{MontoyaApi.class},
                (proxy, method, args) -> "logging".equals(method.getName()) ? logging : null);
    }
}
