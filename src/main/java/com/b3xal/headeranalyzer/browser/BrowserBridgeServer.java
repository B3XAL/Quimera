package com.b3xal.headeranalyzer.browser;

import burp.api.montoya.MontoyaApi;
import com.b3xal.headeranalyzer.analyzer.HeaderAnalysisEngine;
import com.b3xal.headeranalyzer.config.CookiesAndAuthConfig;
import com.b3xal.headeranalyzer.config.QuimeraSettings;
import com.b3xal.headeranalyzer.model.Confidence;
import com.b3xal.headeranalyzer.model.HeaderFinding;
import com.b3xal.headeranalyzer.model.HeaderFinding.Category;
import com.b3xal.headeranalyzer.model.Severity;
import com.b3xal.headeranalyzer.model.UrlAnalysisResult;
import com.b3xal.headeranalyzer.util.JsonUtil;
import com.b3xal.headeranalyzer.util.BackgroundExecutors;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * Loopback-only HTTP server the Quimera browser extension talks to. Hand-rolled over plain
 * {@link ServerSocket}/{@link Socket} (java.base only) rather than {@code com.sun.net.httpserver
 * .HttpServer}, that class lives in the {@code jdk.httpserver} module, and Burp's extension
 * classloader does not resolve it (confirmed: {@code ClassNotFoundException:
 * com.sun.net.httpserver.HttpServer} thrown from Burp's own classloader at runtime), only
 * {@code java.base} is guaranteed available to an extension. This class deliberately implements
 * just enough HTTP/1.1 to serve three small JSON endpoints, not a general-purpose server.
 *
 * Binds strictly to the loopback address, never {@code 0.0.0.0}: nothing off this machine can ever
 * reach it. Sensitive endpoints always require a cryptographically random pairing token and accept
 * browser requests only from recognized extension origins. The bridge itself is disabled by default.
 *
 * Endpoints:
 * <ul>
 *   <li>{@code GET /quimera/v1/ping}, liveness/version probe the extension's popup uses to show a
 *       connected/disconnected indicator.</li>
 *   <li>{@code GET /quimera/v1/scope}, an authenticated, bounded snapshot of hosts observed
 *       in HTTP(S) traffic that currently pass Burp's scope predicate, plus explicit removals
 *       since the previous snapshot.</li>
 *   <li>{@code POST /quimera/v1/ingest}, a {@link BrowserPayload} plus the extension's own
 *       already-computed "localFindings" (as JSON) from the extension. The payload is analyzed
 *       with {@link BrowserStorageAnalyzer}/{@link BrowserDomAnalyzer}, Quimera's own independent
 *       read using its full rule methodology, not just an echo of what the extension's local
 *       engine already found. Cookie-category entries in localFindings are separately considered
 *       for forwarding, see {@link #forwardCookieFindings}, the one part of localFindings this
 *       side does anything with. Either way the combined result is handed to the {@code onResult}
 *       callback (normally {@code QuimeraTab::onResultAdded}, a plain {@link Consumer} here rather
 *       than a direct {@code QuimeraTab} dependency so this class can be started standalone in a
 *       test/dev main, see {@link BrowserBridgeStandalone}) so it lands in Quimera's own Logger/
 *       Cookies &amp; Auth tab/Issues. Also written back in the HTTP response for completeness/
 *       tooling, though the extension's own popup deliberately does not display it, by request,
 *       that UI only ever shows what the extension itself detected.</li>
 * </ul>
 */
public class BrowserBridgeServer {

    private static final int MAX_BODY_BYTES = 1024 * 1024;
    private static final String API_PREFIX = "/quimera/v1";
    private static final int SOCKET_TIMEOUT_MS = 8000;

    private final MontoyaApi api;
    private final QuimeraSettings settings;
    private final HeaderAnalysisEngine engine;
    private final Consumer<UrlAnalysisResult> onResult;
    private final BrowserIssueReporter issueReporter;
    private final boolean burpIntegrationEnabled;
    private final Supplier<ScopeHostTracker.ScopeSnapshot> scopeSnapshot;

    private ServerSocket serverSocket;
    private ExecutorService executor;
    private Thread acceptThread;
    private final ThreadLocal<String> responseOrigin = new ThreadLocal<>();

    public BrowserBridgeServer(MontoyaApi api, QuimeraSettings settings,
                                HeaderAnalysisEngine engine, Consumer<UrlAnalysisResult> onResult) {
        this(api, settings, engine, onResult, ScopeHostTracker.ScopeSnapshot::empty, true);
    }

    public BrowserBridgeServer(MontoyaApi api, QuimeraSettings settings,
                               HeaderAnalysisEngine engine, Consumer<UrlAnalysisResult> onResult,
                               Supplier<ScopeHostTracker.ScopeSnapshot> scopeSnapshot) {
        this(api, settings, engine, onResult, scopeSnapshot, true);
    }

    BrowserBridgeServer(MontoyaApi api, QuimeraSettings settings,
                        HeaderAnalysisEngine engine, Consumer<UrlAnalysisResult> onResult,
                        boolean burpIntegrationEnabled) {
        this(api, settings, engine, onResult, ScopeHostTracker.ScopeSnapshot::empty, burpIntegrationEnabled);
    }

    BrowserBridgeServer(MontoyaApi api, QuimeraSettings settings,
                        HeaderAnalysisEngine engine, Consumer<UrlAnalysisResult> onResult,
                        Supplier<ScopeHostTracker.ScopeSnapshot> scopeSnapshot, boolean burpIntegrationEnabled) {
        this.api = api;
        this.settings = settings;
        this.engine = engine;
        this.onResult = onResult;
        this.issueReporter = new BrowserIssueReporter(api);
        this.burpIntegrationEnabled = burpIntegrationEnabled;
        this.scopeSnapshot = scopeSnapshot;
    }

    /** No-ops if already running. Safe to call from the extension-unload handler unconditionally. */
    public synchronized void start() {
        if (serverSocket != null) return;
        int port = settings.getBrowserBridgePort();
        try {
            serverSocket = new ServerSocket();
            serverSocket.setReuseAddress(true);
            serverSocket.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), port));
            executor = BackgroundExecutors.bounded("Quimera-Bridge", 4, 32);
            acceptThread = new Thread(this::acceptLoop, "Quimera-BrowserBridge-Accept");
            acceptThread.setDaemon(true);
            acceptThread.start();
            api.logging().logToOutput("[Quimera] Browser bridge listening on 127.0.0.1:" + port);
        } catch (IOException ex) {
            serverSocket = null;
            if (executor != null) { executor.shutdownNow(); executor = null; }
            api.logging().logToError("[Quimera] Browser bridge failed to start on port " + port +
                    " (already in use?): " + ex.getMessage());
        }
    }

    /** Stops the server and its thread pool. Safe to call even if never started. */
    public synchronized void shutdown() {
        if (serverSocket != null) {
            try { serverSocket.close(); } catch (IOException ignored) { }
            serverSocket = null;
        }
        if (executor != null) {
            executor.shutdownNow();
            executor = null;
        }
        acceptThread = null;
    }

    /** Stops (if running) and starts again, picking up a changed port/settings. */
    public synchronized void restart() {
        shutdown();
        if (settings.isBrowserBridgeEnabled()) start();
    }

    public synchronized boolean isRunning() {
        return serverSocket != null;
    }

    // ------ Accept loop / connection handling ---------------------------------------------------------------------------------------------------------------------

    /** Runs on its own daemon thread until {@link #shutdown()} closes the socket (accept() then
     * throws and the loop exits). One socket per request, {@code Connection: close}, this is a
     * loopback dev-tool endpoint, not a server built for throughput. */
    private void acceptLoop() {
        ServerSocket localRef = serverSocket;
        while (localRef != null && !localRef.isClosed()) {
            Socket socket;
            try {
                socket = localRef.accept();
            } catch (IOException closed) {
                return; // shutdown() closed the socket, exit quietly
            }
            ExecutorService pool = executor;
            if (pool == null || pool.isShutdown()) {
                closeQuietly(socket);
                return;
            }
            pool.submit(() -> handleConnection(socket));
        }
    }

    private void handleConnection(Socket socket) {
        try {
            socket.setSoTimeout(SOCKET_TIMEOUT_MS);
            InputStream in = socket.getInputStream();
            OutputStream out = socket.getOutputStream();

            RequestHead head = readRequestHead(in);
            if (head == null) return; // empty/malformed request line, nothing sensible to answer
            responseOrigin.set(head.header("origin"));

            if (!allowedOrigin(head.header("origin"))) {
                sendJson(out, 403, Map.of("error", "origin not allowed"));
                return;
            }

            if ("OPTIONS".equalsIgnoreCase(head.method)) {
                sendNoContent(out, 204);
                return;
            }

            String contentLength = head.header("content-length");
            int len = 0;
            if (contentLength != null) {
                try { len = Integer.parseInt(contentLength.trim()); } catch (NumberFormatException ignored) { }
            }
            if (len > MAX_BODY_BYTES) {
                sendJson(out, 413, Map.of("error", "payload too large"));
                return;
            }
            byte[] body = len > 0 ? in.readNBytes(len) : new byte[0];

            route(head, body, out);
        } catch (Exception ex) {
            // Never let one malformed/slow connection take down the accept loop or the server.
            api.logging().logToError("[Quimera] browser bridge connection error: " + ex);
        } finally {
            responseOrigin.remove();
            closeQuietly(socket);
        }
    }

    private void route(RequestHead head, byte[] body, OutputStream out) throws IOException {
        if ((API_PREFIX + "/ping").equals(head.path)) {
            handlePing(head, out);
        } else if ((API_PREFIX + "/ingest").equals(head.path)) {
            handleIngest(head, body, out);
        } else if ((API_PREFIX + "/scope").equals(head.path)) {
            handleScope(head, out);
        } else {
            sendJson(out, 404, Map.of("error", "not found"));
        }
    }

    // ------ Handlers ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

    private void handlePing(RequestHead head, OutputStream out) throws IOException {
        if (!"GET".equalsIgnoreCase(head.method)) {
            sendJson(out, 405, Map.of("error", "method not allowed"));
            return;
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("quimera", true);
        body.put("schemaVersion", 1);
        body.put("bridgeEnabled", settings.isBrowserBridgeEnabled());
        body.put("tokenRequired", settings.isBrowserBridgeTokenEnabled());
        sendJson(out, 200, body);
    }

    private void handleScope(RequestHead head, OutputStream out) throws IOException {
        if (!"GET".equalsIgnoreCase(head.method)) {
            sendJson(out, 405, Map.of("error", "method not allowed"));
            return;
        }
        if (!settings.isBrowserBridgeEnabled()) {
            sendJson(out, 503, Map.of("error", "bridge disabled"));
            return;
        }
        if (!authorized(head)) {
            sendJson(out, 401, Map.of("error", "invalid or missing X-Quimera-Token"));
            return;
        }
        ScopeHostTracker.ScopeSnapshot snapshot = scopeSnapshot.get();
        sendJson(out, 200, Map.of(
                "schemaVersion", 1,
                "hosts", snapshot.hosts(),
                "removedHosts", snapshot.removedHosts()));
    }

    @SuppressWarnings("unchecked")
    private void handleIngest(RequestHead head, byte[] bodyBytes, OutputStream out) throws IOException {
        if (!"POST".equalsIgnoreCase(head.method)) {
            sendJson(out, 405, Map.of("error", "method not allowed"));
            return;
        }
        if (!settings.isBrowserBridgeEnabled()) {
            sendJson(out, 503, Map.of("error", "bridge disabled"));
            return;
        }
        if (!authorized(head)) {
            sendJson(out, 401, Map.of("error", "invalid or missing X-Quimera-Token"));
            return;
        }

        String contentType = head.header("content-type");
        if (contentType == null || !contentType.toLowerCase(Locale.ROOT).contains("application/json")) {
            sendJson(out, 415, Map.of("error", "expected application/json"));
            return;
        }

        try {
            String body = new String(bodyBytes, StandardCharsets.UTF_8);
            Object parsed = JsonUtil.parse(body);
            if (!(parsed instanceof Map<?, ?> root)) {
                sendJson(out, 400, Map.of("error", "expected a JSON object"));
                return;
            }
            Object payloadObj = ((Map<String, Object>) root).get("payload");
            if (!(payloadObj instanceof Map<?, ?> payloadMap)) {
                sendJson(out, 400, Map.of("error", "missing 'payload'"));
                return;
            }
            Object schemaVersion = ((Map<String, Object>) payloadMap).get("schemaVersion");
            if (!isSupportedSchemaVersion(schemaVersion)) {
                sendJson(out, 400, Map.of("error", "unsupported schemaVersion"));
                return;
            }
            BrowserPayload payload = BrowserPayload.fromJson((Map<String, Object>) payloadMap);
            List<HeaderFinding> findings = analyze(payload);
            findings.addAll(forwardCookieFindings(payload, ((Map<String, Object>) root).get("localFindings")));
            findings.sort((a, b) -> a.severity.order - b.severity.order);
            // Visible in Burp's own Extension Output log (Extensions tab > Quimera > Output),
            // confirms every ingest actually reaches this far and exactly how many findings Quimera's
            // own analysis produced for it, without this there was no way to tell "nothing suspicious
            // in this page's Web Storage/DOM" apart from "the request never got this far at all".
            api.logging().logToOutput("[Quimera] browser bridge ingest: " + payload.href + " -> "
                    + findings.size() + " finding(s) (localStorage keys=" + payload.localStorage.size()
                    + ", sessionStorage keys=" + payload.sessionStorage.size() + ")");
            recordResult(payload, findings);
            sendJson(out, 200, Map.of("findings", toJson(findings)));
        } catch (Exception parseError) {
            api.logging().logToError("[Quimera] browser bridge ingest error: " + parseError);
            sendJson(out, 400, Map.of("error", "malformed payload: " + parseError.getMessage()));
        }
    }

    /** JSON numbers are parsed by JsonUtil as Double, so schemaVersion: 1 arrives as 1.0. */
    static boolean isSupportedSchemaVersion(Object value) {
        if (value instanceof Number number) {
            return Double.compare(number.doubleValue(), 1.0d) == 0;
        }
        return value instanceof String string && "1".equals(string.trim());
    }

    private boolean authorized(RequestHead head) {
        return settings.isBrowserBridgeTokenEnabled()
                && constantTimeEquals(settings.getBrowserBridgeToken(), head.header("x-quimera-token"));
    }

    // No cookie-flag analysis here: Quimera already sees Secure/HttpOnly/SameSite/domain-scoping
    // issues from the Set-Cookie header on proxied HTTP traffic via its own CookieAnalyzer, this
    // is for what that path genuinely cannot see any other way (DOM signals, Web Storage). Cookie
    // findings the extension itself already computed (browser.cookies ground truth, including
    // JS-set cookies Burp's proxy never sees at all) are handled separately, see
    // forwardCookieFindings below, only forwarded for cookies Quimera has no HTTP-observed record
    // of, not duplicated for ones it already has.
    private List<HeaderFinding> analyze(BrowserPayload payload) {
        CookiesAndAuthConfig config = settings.cookiesAndAuthConfig();
        List<HeaderFinding> findings = new ArrayList<>();
        findings.addAll(BrowserStorageAnalyzer.analyze(payload, config));
        findings.addAll(BrowserDomAnalyzer.analyze(payload, config));
        findings.sort((a, b) -> a.severity.order - b.severity.order);
        return findings;
    }

    /** Cookie-category findings the extension's own `analyzeCookies` (browser.cookies API, real
     * flags) already computed client-side, arriving in the request body's top-level
     * "localFindings" array alongside "payload". Quimera-burp's own passive Set-Cookie analysis
     * is authoritative whenever it has seen the SAME cookie name on this host from real HTTP
     * traffic (see {@link HeaderAnalysisEngine#hasSeenCookieViaHttp}), so only cookies Quimera
     * genuinely has no HTTP record of (almost always JS-set-only cookies, `document.cookie = ...`,
     * which never produce a Set-Cookie response header for Burp's proxy to see in the first place)
     * get forwarded here, closing that blind spot without duplicating what Quimera already found
     * on its own. Malformed/unexpected entries are skipped individually, never fail the whole
     * ingest over one bad finding. */
    private List<HeaderFinding> forwardCookieFindings(BrowserPayload payload, Object localFindingsObj) {
        List<HeaderFinding> out = new ArrayList<>();
        String host = payload.host;
        if (host == null || host.isBlank()) return out;

        for (Map<String, Object> f : JsonUtil.objectList(localFindingsObj)) {
            try {
                if (!"cookie".equals(JsonUtil.str(f, "category", null))) continue;
                String cookieName = JsonUtil.str(f, "cookieName", null);
                if (cookieName == null || cookieName.isBlank()) continue;
                if (engine.hasSeenCookieViaHttp(host, cookieName)) continue; // Quimera's own wins

                String title = JsonUtil.str(f, "title", null);
                String description = JsonUtil.str(f, "description", "");
                String evidence = JsonUtil.str(f, "evidence", "");
                if (title == null || title.isBlank()) continue;
                Severity severity = Severity.valueOf(JsonUtil.str(f, "severity", "LOW"));
                Confidence confidence = Confidence.valueOf(JsonUtil.str(f, "confidence", "FIRM"));

                // headerName = the real cookie name, not a literal "Set-Cookie": there is no real
                // Set-Cookie header behind this finding to point at (see CookiePanel's
                // ingestSessionLifecycleFindings, which this deliberately matches the shape of),
                // and CookiePanel's UI groups/attaches Category.COOKIE findings by this name.
                out.add(new HeaderFinding(title, cookieName, null,
                        description + " (Detected by the Quimera browser extension via browser.cookies, "
                                + "not from proxied HTTP traffic, most likely a cookie set by JavaScript "
                                + "that never appeared in a Set-Cookie response header.)",
                        evidence, severity, confidence, Category.COOKIE));
            } catch (Exception ignored) {
                // One malformed localFindings entry (unexpected severity/confidence string, missing
                // field) must not drop every other finding in the same ingest.
            }
        }
        return out;
    }

    private void recordResult(BrowserPayload payload, List<HeaderFinding> findings) {
        String url = payload.href != null && !payload.href.isBlank() ? payload.href : payload.origin;
        String host = payload.host != null && !payload.host.isBlank()
                ? payload.host : HeaderAnalysisEngine.extractHost(url);
        String path = payload.path != null && !payload.path.isBlank()
                ? payload.path : HeaderAnalysisEngine.extractPath(url);

        UrlAnalysisResult result = new UrlAnalysisResult(url, host, path, findings, Map.of());
        result.probeLabel = "browser";
        result.statusCode = -1;

        // Populates the request/response viewer panes under the Headers/Cookies & Auth logger,
        // otherwise blank for a browser-bridge result (no real HTTP transaction to show), see
        // BrowserEvidence's own javadoc. Same evidence object also backs the native Issues tab
        // below, one synthetic response, two consumers, not two different renderings of it.
        if (burpIntegrationEnabled) try {
            var evidence = BrowserEvidence.build(payload);
            result.originalRequest = evidence.request();
            result.originalResponse = evidence.response();
            result.rawRequest = evidence.request().toString();
            result.rawResponse = evidence.response().toString();
        } catch (Exception ex) {
            // Belt-and-suspenders: BrowserEvidence.build() itself now falls back internally rather
            // than throwing (see its own safeRequestFromUrl), but if it somehow still fails, don't
            // just log and leave the Request/Response panes silently blank with no clue why, that
            // was the actual symptom this whole try/catch used to produce. Surface the failure
            // reason directly in the panes instead.
            api.logging().logToError("[Quimera] browser bridge evidence-building error: " + ex.getMessage());
            try {
                var fallback = burp.api.montoya.http.message.requests.HttpRequest
                        .httpRequestFromUrl("https://browser-bridge.invalid/evidence-build-failed");
                var fallbackResp = burp.api.montoya.http.message.responses.HttpResponse.httpResponse(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n" +
                        "Quimera could not build evidence for this browser-bridge result: " + ex + "\n" +
                        "The finding(s) themselves are still valid, only this evidence view failed to render.");
                result.originalRequest = fallback;
                result.originalResponse = fallbackResp;
            } catch (Exception ignored) {
                // truly nothing we can do, leave null, findings still get reported below
            }
        }

        onResult.accept(result);

        // Same findings, also raised as native Burp Issues, so a vuln shows up there exactly the
        // same way whether it came from HTTP traffic or the browser bridge (see BrowserIssueReporter).
        if (burpIntegrationEnabled) try {
            issueReporter.report(url, host, payload, findings);
        } catch (Exception ex) {
            api.logging().logToError("[Quimera] browser bridge issue reporting error: " + ex.getMessage());
        }
    }

    // ------ Minimal HTTP/1.1 request parsing ------------------------------------------------------------------------------------------------------------------------

    /** Request line + headers (lowercase-keyed), body is read separately once Content-Length has
     * been sanity-checked against {@link #MAX_BODY_BYTES}. */
    private static final class RequestHead {
        final String method;
        final String path;
        final Map<String, String> headers; // lowercase keys

        RequestHead(String method, String path, Map<String, String> headers) {
            this.method = method;
            this.path = path;
            this.headers = headers;
        }

        String header(String lowerName) { return headers.get(lowerName); }
    }

    private static RequestHead readRequestHead(InputStream in) throws IOException {
        String requestLine = readLine(in);
        if (requestLine == null || requestLine.isBlank()) return null;
        String[] parts = requestLine.split(" ", 3);
        if (parts.length < 2) return null;
        String method = parts[0];
        String path = parts[1];
        int q = path.indexOf('?');
        if (q >= 0) path = path.substring(0, q);

        Map<String, String> headers = new LinkedHashMap<>();
        String line;
        while ((line = readLine(in)) != null && !line.isEmpty()) {
            int colon = line.indexOf(':');
            if (colon > 0) {
                headers.put(line.substring(0, colon).trim().toLowerCase(Locale.ROOT),
                        line.substring(colon + 1).trim());
            }
        }
        return new RequestHead(method, path, headers);
    }

    /** Reads one CRLF- (or bare LF-) terminated line as ISO-8859-1 (HTTP header bytes are ASCII-
     * safe), null on immediate EOF (nothing at all read). */
    private static String readLine(InputStream in) throws IOException {
        java.io.ByteArrayOutputStream buf = new java.io.ByteArrayOutputStream();
        int c;
        boolean any = false;
        while ((c = in.read()) != -1) {
            any = true;
            if (c == '\n') break;
            if (c == '\r') continue;
            buf.write(c);
        }
        if (!any) return null;
        return buf.toString(StandardCharsets.ISO_8859_1);
    }

    // ------ Response writing ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------

    private void sendJson(OutputStream out, int status, Object body) throws IOException {
        byte[] bytes = JsonUtil.write(body).getBytes(StandardCharsets.UTF_8);
        sendRaw(out, status, "application/json; charset=utf-8", bytes);
    }

    private void sendNoContent(OutputStream out, int status) throws IOException {
        sendRaw(out, status, "text/plain; charset=utf-8", new byte[0]);
    }

    /** Browser responses reflect only a validated extension origin; no wildcard CORS is emitted. */
    private void sendRaw(OutputStream out, int status, String contentType, byte[] bytes) throws IOException {
        StringBuilder head = new StringBuilder();
        head.append("HTTP/1.1 ").append(status).append(' ').append(reasonPhrase(status)).append("\r\n");
        head.append("Content-Type: ").append(contentType).append("\r\n");
        head.append("Content-Length: ").append(bytes.length).append("\r\n");
        head.append("Connection: close\r\n");
        String origin = responseOrigin.get();
        if (allowedOrigin(origin) && origin != null && !origin.isBlank()) {
            head.append("Access-Control-Allow-Origin: ").append(origin).append("\r\n");
            head.append("Vary: Origin\r\n");
        }
        head.append("Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n");
        head.append("Access-Control-Allow-Headers: Content-Type, X-Quimera-Token\r\n");
        head.append("Access-Control-Allow-Private-Network: true\r\n");
        head.append("\r\n");
        out.write(head.toString().getBytes(StandardCharsets.ISO_8859_1));
        out.write(bytes);
        out.flush();
    }

    private static String reasonPhrase(int status) {
        return switch (status) {
            case 200 -> "OK";
            case 204 -> "No Content";
            case 400 -> "Bad Request";
            case 401 -> "Unauthorized";
            case 403 -> "Forbidden";
            case 404 -> "Not Found";
            case 405 -> "Method Not Allowed";
            case 413 -> "Payload Too Large";
            case 415 -> "Unsupported Media Type";
            case 503 -> "Service Unavailable";
            default -> "Unknown";
        };
    }

    private static void closeQuietly(Socket socket) {
        try { socket.close(); } catch (IOException ignored) { }
    }

    private static boolean allowedOrigin(String origin) {
        if (origin == null || origin.isBlank()) return true; // non-browser clients/tests
        return origin.startsWith("chrome-extension://")
                || origin.startsWith("moz-extension://")
                || origin.startsWith("safari-web-extension://");
    }

    private static boolean constantTimeEquals(String expected, String provided) {
        if (expected == null || provided == null || expected.isBlank()) return false;
        return MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8),
                provided.getBytes(StandardCharsets.UTF_8));
    }

    // ------ JSON plumbing ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------

    private static List<Map<String, Object>> toJson(List<HeaderFinding> findings) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (HeaderFinding f : findings) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("title", f.issueName);
            m.put("severity", f.severity.name());
            m.put("confidence", f.confidence.name());
            m.put("category", f.category.name());
            m.put("evidence", f.evidence);
            m.put("description", f.description);
            out.add(m);
        }
        return out;
    }
}
