package com.b3xal.headeranalyzer.analyzer;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.b3xal.headeranalyzer.config.QuimeraSettings;
import com.b3xal.headeranalyzer.model.HeaderFinding;
import com.b3xal.headeranalyzer.model.Severity;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Proxy;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Function;
import java.util.zip.GZIPOutputStream;
import com.sun.net.httpserver.HttpServer;

import static org.junit.jupiter.api.Assertions.*;

class HeaderInfluenceProbeTest {
    private static final String URL = "https://example.test/page?id=1";

    @Test
    void transportFailuresAnd503ResumeWithoutLosingCataloguePosition() {
        AtomicInteger calls = new AtomicInteger();
        var rig = new Rig(req -> {
            int call = calls.incrementAndGet();
            if (call <= 3) throw new IllegalStateException("temporary connection failure");
            if (call == 6) return response(req, 503, Map.of("Retry-After", "1"), "busy");
            return response(req, 200, Map.of(), "clean");
        });
        HttpRequest template = request(URL, "GET", Map.of());
        rig.probe.probe(response(template, 200, Map.of(), "clean"));
        assertEquals(rig.requests.get(5).toString(), rig.requests.get(6).toString());
        assertEquals(HeaderInfluenceCatalog.candidates(template).size() + 6, rig.requests.size());
        assertTrue(rig.now.get() >= 30_000);
        assertEquals(rig.probe.lastCoverage().candidates(), rig.probe.lastCoverage().tested());
    }

    @Test
    void disablingWhileRateLimitedCancelsWithoutAnotherRequest() {
        var rig = new Rig(req -> response(req, 429, Map.of("Retry-After", "30"), "busy"));
        rig.onSleep = ignored -> rig.settings.setHeaderInfluenceProbeEnabled(false);
        rig.probe.probe(response(request(URL, "GET", Map.of()), 200, Map.of(), "clean"));
        assertEquals(1, rig.requests.size());
        assertEquals("cancelled", rig.probe.lastCoverage().state());
    }

    @Test
    void observedCustomHeadersBeyond128AreIncluded() {
        Map<String, String> headers = new LinkedHashMap<>();
        for (int i = 0; i < 150; i++) headers.put("X-Custom-" + i, "original");
        var candidates = HeaderInfluenceCatalog.candidates(request(URL, "GET", headers));
        assertEquals(150, candidates.stream().filter(c -> c.name().startsWith("x-custom-")).count());
    }

    @Test
    void typedTraceRecipesHaveValidTraceIds() {
        for (var candidate : HeaderInfluenceCatalog.reviewed()) {
            String value = candidate.value("0123456789abcdef0123456789abcdef", false);
            if (candidate.name().equals("traceparent"))
                assertTrue(value.matches("00-[0-9a-f]{32}-[0-9a-f]{16}-0[01]"), value);
            if (candidate.name().equals("x-cloud-trace-context"))
                assertTrue(value.matches("[0-9a-f]{32}/[0-9]+;o=[01]"), value);
        }
    }

    @Test
    void documentedVariantsPrecedeUntypedDiscovery() {
        var candidates = HeaderInfluenceCatalog.candidates(request(URL, "GET", Map.of()));
        int firstDiscovery = java.util.stream.IntStream.range(0, candidates.size())
                .filter(i -> candidates.get(i).family().equals("discovery")).findFirst().orElseThrow();
        assertTrue(candidates.subList(firstDiscovery, candidates.size()).stream()
                .allMatch(c -> c.family().equals("discovery")));
        assertTrue(candidates.subList(0, firstDiscovery).stream()
                .anyMatch(c -> c.name().equals("accept") && c.seed().equals("application/vnd.api+json")));
    }

    @Test
    void dynamicBodyDoesNotHideStableHeaderInfluence() {
        AtomicInteger count = new AtomicInteger();
        var rig = new Rig(req -> response(req, 200, Map.of("Content-Type", "text/plain", "X-Layout",
                "original".equals(req.headerValue("X-Display")) ? "default" : "alternate"),
                "dynamic counter " + count.incrementAndGet()));
        assertTrue(rig.probe.probe(rig.exchange(request(URL, "GET", Map.of("X-Display", "original"))))
                .stream().flatMap(r -> r.findings.stream())
                .anyMatch(f -> f.issueName.equals("Request header controls response: x-display")));
    }

    @Test
    void fullCatalogueRunsOnEverySelectedContextWithoutOriginQuota() {
        var rig = new Rig(req -> response(req, 200, Map.of(), "same"));
        for (String host : List.of("example.test", "EXAMPLE.test:443", "example.test")) {
            int before = rig.requests.size();
            rig.probe.probe(rig.exchange(request("https://" + host + "/page", "GET", Map.of())));
            assertTrue(rig.requests.size() - before > 512);
            assertEquals(rig.probe.lastCoverage().candidates(), rig.probe.lastCoverage().tested());
            assertTrue(rig.probe.lastCoverage().state().startsWith("completed"));
        }
    }

    @Test
    void encodedActionPathsAndMalformedAuthoritiesAreNotReplayed() {
        for (String url : List.of("https://example.test/%6Cogout", "https://example.test/?action=%64elete",
                "https://user@example.test/page", "https:/page"))
            assertFalse(HeaderInfluenceProbe.eligible(response(request(url, "GET", Map.of()), 200, Map.of(), "")), url);
    }

    @Test
    void stackedCompressionAndExplicitCharsetsAreDecodedStrictly() throws Exception {
        String marker = "0123456789abcdef0123456789abcdef";
        byte[] bytes = marker.getBytes(StandardCharsets.UTF_16LE);
        for (int n = 0; n < 2; n++) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            try (GZIPOutputStream gzip = new GZIPOutputStream(out)) { gzip.write(bytes); }
            bytes = out.toByteArray();
        }
        HttpRequest req = request(URL, "GET", Map.of());
        var snapshot = HeaderInfluenceResponse.of(responseBytes(req, 200,
                Map.of("Content-Type", "text/plain; charset=\"UTF-16LE\"", "Content-Encoding", "gzip, gzip"), bytes));
        assertTrue(snapshot.bodyComplete);
        assertFalse(snapshot.reflections(marker).isEmpty());
        assertFalse(HeaderInfluenceResponse.of(responseBytes(req, 200,
                Map.of("Content-Type", "text/plain; charset=utf-8"), new byte[]{(byte) 0xc3, 0x28})).bodyComplete);
        assertFalse(HeaderInfluenceResponse.of(response(req, 200,
                Map.of("Content-Type", "application/octet-stream; name=json"), marker)).bodyComplete);
    }

    @Test
    void newlyDocumentedCmsDisclosureIsSeparateFromInfluence() {
        var rig = new Rig(req -> response(req, 200, req.hasHeader("X-Include-Metadata")
                ? Map.of("X-WP-DoingItWrong", "function_name since 6.0") : Map.of(), "same"));
        var findings = rig.probe.probe(rig.exchange(request(URL, "GET", Map.of())))
                .stream().flatMap(r -> r.findings.stream()).toList();
        assertTrue(findings.stream().anyMatch(f -> f.category == HeaderFinding.Category.INFORMATION_DISCLOSURE
                && f.headerName.equals("x-wp-doingitwrong")));
    }

    @Test
    void reflectsExistingCustomHeaderAsInfoAndKeepsCleanRetestTemplate() {
        HttpRequest template = request(URL, "GET", Map.of("X-Display-Name", "original", "Cookie", "sid=kept"));
        var rig = new Rig(req -> response(req, 200, Map.of("Content-Type", "text/html"),
                "<p>" + req.headerValue("X-Display-Name") + "</p>"));
        var results = rig.probe.probe(rig.exchange(template));
        var result = results.stream().filter(r -> r.findings.stream().anyMatch(f ->
                f.issueName.equals("Request header value reflected: x-display-name"))).findFirst().orElseThrow();
        assertEquals(Severity.INFORMATION, result.findings.get(0).severity);
        assertEquals(6, result.probeExchanges.size());
        assertNotEquals("original", result.originalRequest.headerValue("X-Display-Name"));
        assertEquals(result.probeExchanges.get(2).request().toString(), result.originalRequest.toString());
        assertTrue(rig.requests.stream().allMatch(r -> "sid=kept".equals(r.headerValue("Cookie"))));
        assertTrue(result.findings.get(0).evidence.contains("HTML text"));
        int before = rig.requests.size();
        assertNotNull(rig.probe.retest(result.probeLabel, result.probeExchanges.get(0).request()));
        assertEquals(6, rig.requests.size() - before, "retest must replay only this header recipe");
    }

    @Test
    void newHeadersAreInsertedIndividuallyAndGetIndividualEvidence() {
        HttpRequest template = request(URL, "GET", Map.of());
        var rig = new Rig(req -> response(req, 200, Map.of("Content-Type", "text/html"),
                "<a href='https://" + Objects.toString(req.headerValue("X-Forwarded-Host"), "original") + "'>go</a>"));
        var results = rig.probe.probe(rig.exchange(template));
        var found = results.stream().flatMap(r -> r.findings.stream())
                .filter(f -> f.issueName.equals("Request header value reflected: x-forwarded-host")).findFirst();
        assertTrue(found.isPresent());
        assertTrue(rig.requests.stream().allMatch(req -> req.headers().size() <= 3), "every new candidate is tested alone");
        for (var result : results) for (int index : new int[]{2, 4}) {
            assertEquals(3, result.probeExchanges.get(index).request().headers().size(),
                    "confirmation contains candidate plus fixed marker and encoding negotiation");
        }
    }

    @Test
    void nonReflectingLiteralResponseSwitchIsInfo() {
        HttpRequest template = request(URL, "GET", Map.of("Accept", "application/json"));
        var rig = new Rig(req -> response(req, 200, Map.of("Content-Type", "text/plain"),
                "text/html".equals(req.headerValue("Accept")) ? "rendered representation" : "data representation"));
        var findings = rig.probe.probe(rig.exchange(template)).stream().flatMap(r -> r.findings.stream()).toList();
        assertTrue(findings.stream().anyMatch(f -> f.issueName.equals("Request header controls response: accept")
                && f.severity == Severity.INFORMATION));
        assertTrue(findings.stream().noneMatch(f -> f.issueName.contains("XSS")));
    }

    @Test
    void requestOnlyMarkersAndRoutineDynamicIdsDoNotBecomeFindings() {
        AtomicInteger count = new AtomicInteger();
        var rig = new Rig(req -> response(req, 200,
                Map.of("Content-Type", "text/plain", "X-Request-Id", "id-" + count.incrementAndGet()), "same body"));
        assertTrue(rig.probe.probe(rig.exchange(request(URL, "GET", Map.of("X-Not-Echoed", "original")))).isEmpty());
    }

    @Test
    void errorStatusesAndSoftErrorBodiesCannotConfirmReflection() {
        for (int status : new int[]{401, 404, 500}) {
            var rig = new Rig(req -> response(req, !"original".equals(req.headerValue("X-Display")) ? status : 200,
                    Map.of("Content-Type", "text/html"), Objects.toString(req.headerValue("X-Display"), "clean")));
            HttpRequest template = request(URL, "GET", Map.of("X-Display", "original"));
            assertTrue(rig.probe.probe(response(template, 200, Map.of(), "clean")).isEmpty());
            assertTrue(rig.probe.lastCoverage().suppressed() > 0);
        }
        var rig = new Rig(req -> response(req, 200, Map.of("Content-Type", "text/html"),
                "<title>Just a moment</title>" + req.headerValue("X-Display")));
        assertTrue(rig.probe.probe(rig.exchange(request(URL, "GET", Map.of("X-Display", "original")))).isEmpty());
    }

    @Test
    void rejectsPersistenceOfProbeValueIntoCleanControls() {
        String[] saved = {"original"};
        var rig = new Rig(req -> {
            String value = req.headerValue("X-Display");
            if (value != null && !value.equals("original")) saved[0] = value;
            return response(req, 200, Map.of("Content-Type", "text/plain"), saved[0]);
        });
        assertTrue(rig.probe.probe(rig.exchange(request(URL, "GET", Map.of("X-Display", "original")))).isEmpty());
    }

    @Test
    void separatesDisclosureFromReflectionAndOrdinaryInfluence() {
        var rig = new Rig(req -> {
            Map<String, String> headers = new LinkedHashMap<>(Map.of("Content-Type", "text/plain"));
            if (req.hasHeader("Fastly-Debug")) headers.put("Fastly-Debug-Path", "cache-internal-node-1");
            return response(req, 200, headers, "same");
        });
        var findings = rig.probe.probe(rig.exchange(request(URL, "GET", Map.of())))
                .stream().flatMap(r -> r.findings.stream()).toList();
        assertTrue(findings.stream().anyMatch(f -> f.category == HeaderFinding.Category.INFORMATION_DISCLOSURE
                && f.headerName.equals("fastly-debug-path")));
        assertTrue(findings.stream().anyMatch(f -> f.issueName.equals("Request header controls response: fastly-debug")
                && f.severity == Severity.INFORMATION));
    }

    @Test
    void individualDiscoveryAvoidsRejectionOfMultiHeaderBatches() {
        var rig = new Rig(req -> {
            if (req.headers().size() > 3) return response(req, 431, Map.of(), "too many headers");
            return response(req, 200, Map.of("Content-Type", "text/plain"),
                    Objects.toString(req.headerValue("X-Forwarded-Host"), "clean"));
        });
        var findings = rig.probe.probe(rig.exchange(request(URL, "GET", Map.of())))
                .stream().flatMap(r -> r.findings.stream()).toList();
        assertTrue(findings.stream().anyMatch(f -> f.issueName.equals("Request header value reflected: x-forwarded-host")));
        assertEquals(0, rig.probe.lastCoverage().suppressed());
    }

    @Test
    void completeCatalogueRespectsDelayAndShutdown() {
        var rig = new Rig(req -> response(req, 200, Map.of(), "clean"));
        HttpRequest template = request(URL, "GET", Map.of());
        rig.probe.probe(rig.exchange(template));
        assertEquals(HeaderInfluenceCatalog.candidates(template).size() + 2, rig.requests.size());
        assertTrue(rig.requests.size() > 512);
        assertTrue(rig.now.get() >= (rig.requests.size() - 1L) * rig.settings.getHeaderInfluenceDelayMillis());
        assertTrue(rig.probe.lastCoverage().state().startsWith("completed"));
        rig.probe.shutdown();
        int before = rig.requests.size();
        rig.probe.probe(rig.exchange(template));
        assertEquals(before, rig.requests.size());
    }

    @Test
    void rateLimitPausesThenRetriesSameRequestAndFinishesCatalogue() {
        AtomicInteger count = new AtomicInteger();
        var rig = new Rig(req -> count.incrementAndGet() == 3
                ? response(req, 429, Map.of("Retry-After", "2"), "limited")
                : response(req, 200, Map.of(), "clean"));
        HttpRequest template = request(URL, "GET", Map.of());
        rig.probe.probe(response(template, 200, Map.of(), "clean"));
        assertEquals(rig.requests.get(2).toString(), rig.requests.get(3).toString());
        assertEquals(HeaderInfluenceCatalog.candidates(template).size() + 3, rig.requests.size());
        assertTrue(rig.now.get() >= (rig.requests.size() - 2L) * rig.settings.getHeaderInfluenceDelayMillis() + 2000);
        assertEquals(rig.probe.lastCoverage().candidates(), rig.probe.lastCoverage().tested());
    }

    @Test
    void unreadableProbeBodiesAloneCannotConfirmInfluence() throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (GZIPOutputStream gzip = new GZIPOutputStream(bytes)) {
            gzip.write("clean".getBytes(StandardCharsets.UTF_8));
        }
        byte[] valid = bytes.toByteArray();
        var rig = new Rig(req -> responseBytes(req, 200,
                Map.of("Content-Type", "text/plain", "Content-Encoding", "gzip"),
                "original".equals(req.headerValue("X-Display")) ? valid : new byte[]{1, 2, 3}));
        assertTrue(rig.probe.probe(rig.exchange(request(URL, "GET",
                Map.of("X-Display", "original")))).isEmpty());
        assertTrue(rig.probe.lastCoverage().inconclusive() > 0);
    }

    @Test
    void headerInfluenceRemainsDetectableWithUnreadableProbeBody() throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (GZIPOutputStream gzip = new GZIPOutputStream(bytes)) {
            gzip.write("clean".getBytes(StandardCharsets.UTF_8));
        }
        byte[] valid = bytes.toByteArray();
        var rig = new Rig(req -> {
            boolean clean = "original".equals(req.headerValue("X-Display"));
            return responseBytes(req, 200, Map.of("Content-Type", "text/plain",
                    "Content-Encoding", "gzip", "X-Representation", clean ? "default" : "alternate"),
                    clean ? valid : new byte[]{1, 2, 3});
        });
        assertTrue(rig.probe.probe(rig.exchange(request(URL, "GET", Map.of("X-Display", "original"))))
                .stream().flatMap(r -> r.findings.stream())
                .anyMatch(f -> f.issueName.equals("Request header controls response: x-display")));
    }

    @Test
    void handlesBoundedGzipAndMarksUnsupportedOrOversizedBodies() throws Exception {
        String marker = "0123456789abcdef0123456789abcdef";
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (GZIPOutputStream gzip = new GZIPOutputStream(bytes)) { gzip.write(marker.getBytes(StandardCharsets.UTF_8)); }
        HttpRequest req = request(URL, "GET", Map.of());
        var snapshot = HeaderInfluenceResponse.of(responseBytes(req, 200,
                Map.of("Content-Type", "text/plain", "Content-Encoding", "gzip"), bytes.toByteArray()));
        assertFalse(snapshot.reflections(marker).isEmpty());
        assertFalse(HeaderInfluenceResponse.of(response(req, 200,
                Map.of("Content-Encoding", "br"), marker)).bodyComplete);
        assertFalse(HeaderInfluenceResponse.of(response(req, 200, Map.of(),
                "a".repeat(HeaderInfluenceResponse.MAX_BODY + 1))).bodyComplete);
    }

    @Test
    void excludesUnsafeReplayAndSensitiveHeadersAndLoadsBroadCatalogue() {
        assertFalse(HeaderInfluenceProbe.eligible(response(request(URL, "POST", Map.of()), 200, Map.of(), "")));
        assertFalse(HeaderInfluenceProbe.eligible(response(request("https://example.test/logout", "GET", Map.of()), 200, Map.of(), "")));
        assertFalse(HeaderInfluenceProbe.eligible(response(request(URL, "GET", Map.of()), 404, Map.of(), "")));
        for (String name : List.of("Host", "Content-Length", "Cookie", "Authorization", "X-WP-Nonce", "X-CSRF-Token")) {
            assertFalse(HeaderInfluenceCatalog.allowed(name), name);
        }
        assertTrue(HeaderInfluenceCatalog.reviewed().size() > 150);
        assertTrue(HeaderInfluenceCatalog.discovery().size() > 1000);
        assertTrue(HeaderInfluenceCatalog.discovery().stream().noneMatch(c -> Set.of("server", "x-powered-by",
                "content-length", "authorization", "set-cookie").contains(c.name())));
        assertTrue(HeaderInfluenceCatalog.reviewed().stream().map(HeaderInfluenceCatalog.Candidate::name).distinct().count() > 100);
        assertTrue(HeaderInfluenceCatalog.reviewed().stream().allMatch(c -> c.source().startsWith("https://")));
    }

    @Test
    void findingsArePublishedDuringScanAndDoNotStopAtTwelve() {
        Map<String, String> input = new LinkedHashMap<>();
        for (int i = 0; i < 20; i++) input.put("X-Audit-" + i, "original");
        var rig = new Rig(req -> response(req, 200, Map.of("Content-Type", "text/plain"),
                req.headers().stream().filter(h -> h.name().toLowerCase(Locale.ROOT).startsWith("x-audit-"))
                    .map(HttpHeader::value).reduce("", (a, b) -> a + " " + b)));
        AtomicInteger published = new AtomicInteger();
        rig.probe.probe(rig.exchange(request(URL, "GET", input)), result -> {
            assertFalse(rig.probe.lastCoverage().state().startsWith("completed"));
            published.incrementAndGet();
        });
        assertEquals(20, published.get());
        assertEquals(rig.probe.lastCoverage().candidates(), rig.probe.lastCoverage().tested());
    }

    @Test
    void detectsChangedDisclosureValueNotJustNewHeaderNames() {
        var rig = new Rig(req -> response(req, 200,
                Map.of("Content-Type", "text/plain", "X-Cache-Key",
                        req.hasHeader("Fastly-Debug") ? "origin.internal/private/cache-key" : "public-key"), "same"));
        var findings = rig.probe.probe(rig.exchange(request(URL, "GET", Map.of())))
                .stream().flatMap(r -> r.findings.stream()).toList();
        assertTrue(findings.stream().anyMatch(f -> f.issueName.startsWith("Header-triggered disclosure: fastly-debug")
                && f.headerValue.equals("origin.internal/private/cache-key")));
    }

    @Test
    @org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable(named = "QUIMERA_APACHE_FIXTURE_URL", matches = "http://127\\.0\\.0\\.1:.*")
    void realApacheModHeadersConfirmsResponseHeaderReflection() {
        String url = System.getenv("QUIMERA_APACHE_FIXTURE_URL");
        HttpClient client = HttpClient.newHttpClient();
        var rig = new Rig(req -> {
            try {
                var builder = java.net.http.HttpRequest.newBuilder(URI.create(req.url()));
                req.headers().forEach(h -> builder.header(h.name(), h.value()));
                var actual = client.send(builder.GET().build(), java.net.http.HttpResponse.BodyHandlers.ofByteArray());
                Map<String, String> headers = new LinkedHashMap<>();
                actual.headers().map().forEach((name, values) -> headers.put(name, String.join(",", values)));
                return responseBytes(req, actual.statusCode(), headers, actual.body());
            } catch (Exception ex) { throw new IllegalStateException(ex); }
        });
        var findings = rig.probe.probe(rig.exchange(request(url, "GET", Map.of("X-Display", "original"))))
                .stream().flatMap(r -> r.findings.stream()).toList();
        assertTrue(findings.stream().anyMatch(f -> f.issueName.equals("Request header value reflected: x-display")
                && f.evidence.contains("response header x-audit-echo")));
    }

    @Test
    void realLocalHttpRoundTripsConfirmHeaderEchoWithoutExternalTargets() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            String echo = Objects.toString(exchange.getRequestHeaders().getFirst("X-Display"), "clean");
            byte[] body = ("<p>" + echo + "</p>").getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "text/html");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();
        try {
            String url = "http://127.0.0.1:" + server.getAddress().getPort() + "/";
            HttpClient client = HttpClient.newHttpClient();
            var rig = new Rig(req -> {
                try {
                    var builder = java.net.http.HttpRequest.newBuilder(URI.create(req.url()));
                    req.headers().forEach(h -> builder.header(h.name(), h.value()));
                    var actual = client.send(builder.GET().build(), java.net.http.HttpResponse.BodyHandlers.ofByteArray());
                    return responseBytes(req, actual.statusCode(), Map.of("Content-Type", "text/html"), actual.body());
                } catch (Exception ex) { throw new IllegalStateException(ex); }
            });
            HttpRequest template = request(url, "GET", Map.of("X-Display", "original"));
            assertTrue(rig.probe.probe(rig.exchange(template)).stream().flatMap(r -> r.findings.stream())
                    .anyMatch(f -> f.issueName.equals("Request header value reflected: x-display")));
        } finally { server.stop(0); }
    }

    private static final class Rig {
        final QuimeraSettings settings = new QuimeraSettings();
        final AtomicLong now = new AtomicLong();
        final List<HttpRequest> requests = new ArrayList<>();
        java.util.function.LongConsumer onSleep = ignored -> {};
        final Function<HttpRequest, HttpRequestResponse> responder;
        final HeaderInfluenceProbe probe;
        Rig(Function<HttpRequest, HttpRequestResponse> responder) {
            this.responder = responder;
            probe = new HeaderInfluenceProbe(null, settings, req -> {
                requests.add(req); return responder.apply(req);
            }, now::get, millis -> { now.addAndGet(millis); onSleep.accept(millis); });
        }
        HttpRequestResponse exchange(HttpRequest req) { return responder.apply(req); }
    }

    private interface Call { Object apply(Object[] args); }
    @SuppressWarnings("unchecked")
    private static <T> T fake(Class<T> type, Map<String, Call> methods) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, (p, m, args) -> {
            if (methods.containsKey(m.getName())) return methods.get(m.getName()).apply(args);
            if (m.getName().equals("equals")) return p == args[0];
            if (m.getName().equals("hashCode")) return System.identityHashCode(p);
            if (m.getReturnType() == boolean.class) return false;
            if (m.getReturnType() == int.class) return 0;
            return null;
        });
    }

    static HttpRequest request(String url, String method, Map<String, String> input) {
        Map<String, String> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER); headers.putAll(input);
        return fake(HttpRequest.class, Map.of(
                "url", a -> url, "method", a -> method, "headers", a -> headerList(headers),
                "headerValue", a -> headers.get((String) a[0]),
                "hasHeader", a -> headers.containsKey((String) a[0]),
                "header", a -> headers.containsKey((String) a[0]) ? header((String) a[0], headers.get((String) a[0])) : null,
                "withHeader", a -> { var copy = new TreeMap<>(headers); copy.put((String) a[0], (String) a[1]); return request(url, method, copy); },
                "toString", a -> method + " " + url + "\r\n" + headers));
    }
    private static HttpHeader header(String name, String value) {
        return fake(HttpHeader.class, Map.of("name", a -> name, "value", a -> value,
                "toString", a -> name + ": " + value));
    }
    private static List<HttpHeader> headerList(Map<String, String> headers) {
        return headers.entrySet().stream().map(e -> header(e.getKey(), e.getValue())).toList();
    }
    private static HttpRequestResponse response(HttpRequest req, int status, Map<String, String> headers, String body) {
        return responseBytes(req, status, headers, body.getBytes(StandardCharsets.UTF_8));
    }
    private static HttpRequestResponse responseBytes(HttpRequest req, int status, Map<String, String> input, byte[] bytes) {
        Map<String, String> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER); headers.putAll(input);
        ByteArray body = fake(ByteArray.class, Map.of("length", a -> bytes.length, "getBytes", a -> bytes));
        HttpResponse response = fake(HttpResponse.class, Map.of("statusCode", a -> (short) status,
                "headers", a -> headerList(headers), "headerValue", a -> headers.get((String) a[0]),
                "body", a -> body, "bodyToString", a -> new String(bytes, StandardCharsets.UTF_8),
                "toString", a -> "HTTP/1.1 " + status + "\r\n" + headers + "\r\n\r\n" + new String(bytes, StandardCharsets.UTF_8)));
        return fake(HttpRequestResponse.class, Map.of("request", a -> req, "response", a -> response));
    }
}
