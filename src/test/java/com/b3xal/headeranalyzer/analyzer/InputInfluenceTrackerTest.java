package com.b3xal.headeranalyzer.analyzer;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.b3xal.headeranalyzer.browser.BrowserPayload;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class InputInfluenceTrackerTest {

    @Test
    void recordsOnlyExactMeaningfulInputPropagation() {
        AtomicLong now = new AtomicLong(10_000);
        InputInfluenceTracker tracker = new InputInfluenceTracker(now::get);

        var findings = tracker.observeHttp(exchange("https://example.test/page?next=route-marker-123",
                parameter("next", "route-marker-123", HttpParameterType.URL),
                List.of(header("X-Next", "route-marker-123"))));

        assertEquals(1, findings.size());
        assertTrue(findings.get(0).evidence.contains("route-marker-123"));
        assertTrue(tracker.observeHttp(exchange("https://example.test/page?page=1",
                parameter("page", "1", HttpParameterType.URL), List.of(header("X-Other", "1")))).isEmpty());
    }

    @Test
    void confirmsStorageOnlyForTheSameOriginAndWithinTheFiveMinuteWindow() {
        AtomicLong now = new AtomicLong(10_000);
        InputInfluenceTracker tracker = new InputInfluenceTracker(now::get);
        tracker.observeHttp(exchange("https://example.test/page?next=route-marker-123",
                parameter("next", "route-marker-123", HttpParameterType.URL), List.of()));
        BrowserPayload matching = new BrowserPayload("https://example.test", "", "example.test", "/", "",
                Map.of("next", "route-marker-123"), Map.of(), List.of(), new BrowserPayload.DomSignals(List.of()));
        assertEquals(1, tracker.observeBrowser(matching).size());

        now.addAndGet(InputInfluenceTracker.WINDOW_MILLIS + 1);
        assertTrue(tracker.observeBrowser(matching).isEmpty());
    }

    @Test
    void detectsParameterValueWrittenIntoANewCookieInTheSameResponse() {
        AtomicLong now = new AtomicLong(10_000);
        InputInfluenceTracker tracker = new InputInfluenceTracker(now::get);
        var findings = tracker.observeHttp(exchange("https://example.test/login?token=inputmarker1234567890",
                parameter("token", "inputmarker1234567890", HttpParameterType.URL),
                List.of(header("Set-Cookie", "session=inputmarker1234567890; Path=/; HttpOnly"))));
        assertEquals(1, findings.size());
        assertTrue(findings.get(0).issueName.contains("propagated to cookie"));
    }

    @Test
    void detectsParameterFromAnEarlierRequestWrittenIntoACookieLater() {
        // Multi-step flow: value supplied in step 1 only becomes a Set-Cookie several requests later.
        AtomicLong now = new AtomicLong(10_000);
        InputInfluenceTracker tracker = new InputInfluenceTracker(now::get);
        assertTrue(tracker.observeHttp(exchange("https://example.test/step1?ref=inputmarker1234567890",
                parameter("ref", "inputmarker1234567890", HttpParameterType.URL), List.of())).isEmpty());
        now.addAndGet(30_000);
        var findings = tracker.observeHttp(exchange("https://example.test/step5?page=1",
                parameter("page", "1", HttpParameterType.URL),
                List.of(header("Set-Cookie", "sid=inputmarker1234567890; Path=/"))));
        assertEquals(1, findings.size());
        assertTrue(findings.get(0).issueName.contains("propagated to cookie"));
    }

    @Test
    void shortLowSignalValuesDoNotFalsePositive() {
        AtomicLong now = new AtomicLong(10_000);
        InputInfluenceTracker tracker = new InputInfluenceTracker(now::get);
        // csrf is a low-signal name and the value is short: an exact echo into a same-named cookie
        // must not be reported (too collision-prone).
        assertTrue(tracker.observeHttp(exchange("https://example.test/f?csrf=shortvv",
                parameter("csrf", "shortvv", HttpParameterType.URL),
                List.of(header("Set-Cookie", "csrf=shortvv; Path=/")))).isEmpty());
    }

    @Test
    void propagationIsNotMatchedAcrossDifferentHosts() {
        AtomicLong now = new AtomicLong(10_000);
        InputInfluenceTracker tracker = new InputInfluenceTracker(now::get);
        tracker.observeHttp(exchange("https://a.example.test/step1?ref=inputmarker1234567890",
                parameter("ref", "inputmarker1234567890", HttpParameterType.URL), List.of()));
        assertTrue(tracker.observeHttp(exchange("https://b.example.test/step2?page=1",
                parameter("page", "1", HttpParameterType.URL),
                List.of(header("Set-Cookie", "sid=inputmarker1234567890; Path=/")))).isEmpty(),
                "a value from a different host must not be linked");
    }

    @Test
    void propagationExpiresAfterTheWindow() {
        AtomicLong now = new AtomicLong(10_000);
        InputInfluenceTracker tracker = new InputInfluenceTracker(now::get);
        tracker.observeHttp(exchange("https://example.test/step1?ref=inputmarker1234567890",
                parameter("ref", "inputmarker1234567890", HttpParameterType.URL), List.of()));
        now.addAndGet(InputInfluenceTracker.WINDOW_MILLIS + 1);
        assertTrue(tracker.observeHttp(exchange("https://example.test/step9?page=1",
                parameter("page", "1", HttpParameterType.URL),
                List.of(header("Set-Cookie", "sid=inputmarker1234567890; Path=/")))).isEmpty(),
                "a value older than the window must not be linked");
    }

    private static HttpRequestResponse exchange(String url, ParsedHttpParameter parameter, List<HttpHeader> headers) {
        HttpRequest request = fake(HttpRequest.class, Map.of("url", ignored -> url, "parameters", ignored -> List.of(parameter)));
        ByteArray body = fake(ByteArray.class, Map.of("length", ignored -> 0));
        HttpResponse response = fake(HttpResponse.class, Map.of("headers", ignored -> headers, "body", ignored -> body));
        return fake(HttpRequestResponse.class, Map.of("request", ignored -> request, "response", ignored -> response));
    }

    private static ParsedHttpParameter parameter(String name, String value, HttpParameterType type) {
        return fake(ParsedHttpParameter.class, Map.of("name", ignored -> name, "value", ignored -> value, "type", ignored -> type));
    }

    private static HttpHeader header(String name, String value) {
        return fake(HttpHeader.class, Map.of("name", ignored -> name, "value", ignored -> value));
    }

    @SuppressWarnings("unchecked")
    private static <T> T fake(Class<T> type, Map<String, java.util.function.Function<Object[], Object>> calls) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, (proxy, method, args) -> {
            var call = calls.get(method.getName());
            if (call != null) return call.apply(args == null ? new Object[0] : args);
            if (method.getName().equals("equals")) return proxy == args[0];
            if (method.getName().equals("hashCode")) return System.identityHashCode(proxy);
            if (method.getReturnType() == boolean.class) return false;
            if (method.getReturnType() == int.class || method.getReturnType() == short.class) return 0;
            return null;
        });
    }
}
