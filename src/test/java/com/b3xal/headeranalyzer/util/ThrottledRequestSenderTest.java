package com.b3xal.headeranalyzer.util;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.burpsuite.BurpSuite;
import burp.api.montoya.core.BurpSuiteEdition;
import burp.api.montoya.core.Version;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.execution.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Proves ThrottledRequestSender's fallback and shutdown logic against fake but behaviourally
 * faithful Montoya interfaces (same dynamic-proxy mocking style already used by
 * SafeLoggingTest/CacheKeyDisclosureProbeTest).
 *
 * The real engine-creation sequence ({@code RequestEngineOptions.requestEngineOptions()},
 * {@code ResourcePool.defaultResourcePool()}) needs a live Burp instance and throws in a plain
 * JVM, so the "engine actually starts and a request round-trips through it" path cannot be
 * exercised here (same limitation as {@code PersistedObject}/{@code PersistedList}). What IS
 * fully testable: the Community Edition and engine-creation-failure fallbacks (both complete
 * quickly, no real timeout wait), and that shutdown() unblocks a caller stuck waiting via the
 * package-private test seam (an already-"running" fake execution that never calls back).
 */
class ThrottledRequestSenderTest {

    @Test
    void communityEditionFallsBackToDirectSendRequestWithoutTryingToCreateAnEngine() {
        AtomicBoolean createEngineCalled = new AtomicBoolean(false);
        HttpRequestResponse canned = proxy(HttpRequestResponse.class, Map.of());
        HttpRequest req = proxy(HttpRequest.class, Map.of());

        MontoyaApi api = fakeApi(BurpSuiteEdition.COMMUNITY_EDITION,
                r -> canned, opts -> { createEngineCalled.set(true); return null; });

        ThrottledRequestSender sender = new ThrottledRequestSender(api, "test");
        assertSame(canned, sender.send(req));
        assertFalse(createEngineCalled.get(), "Community Edition must never attempt createRequestEngine");
    }

    @Test
    void engineCreationFailureFallsBackToDirectSendRequestInstead() {
        HttpRequestResponse canned = proxy(HttpRequestResponse.class, Map.of());
        HttpRequest req = proxy(HttpRequest.class, Map.of());

        MontoyaApi api = fakeApi(BurpSuiteEdition.PROFESSIONAL,
                r -> canned, opts -> { throw new RuntimeException("no license for this feature"); });

        ThrottledRequestSender sender = new ThrottledRequestSender(api, "test");
        assertSame(canned, sender.send(req));
    }

    @Test
    void shutdownUnblocksACallerStillWaitingOnSend() throws Exception {
        // Package-private test seam: an already-"running" execution whose queue() does nothing,
        // exactly the state a caller is stuck in if the run never calls back for a queued request.
        RequestExecution fakeExecution = proxy(RequestExecution.class, Map.of(
                "queue", a -> null,
                "lifetime", a -> proxy(RequestExecutionLifetime.class, Map.of())));
        MontoyaApi api = fakeApi(BurpSuiteEdition.PROFESSIONAL, r -> {
            throw new AssertionError("must never fall back to a direct send while the engine is live");
        }, opts -> { throw new AssertionError("must not attempt to create a new engine via the test seam"); });

        ThrottledRequestSender sender = new ThrottledRequestSender(api, fakeExecution);
        HttpRequest req = proxy(HttpRequest.class, Map.of());
        HttpRequestResponse[] result = new HttpRequestResponse[1];
        Thread t = new Thread(() -> result[0] = sender.send(req));
        t.start();
        t.join(2000);
        assertTrue(t.isAlive(), "sanity check: send() should still be blocked, nothing drains the queue");

        sender.shutdown();
        t.join(5000);
        assertFalse(t.isAlive(), "send() must return once shutdown() force-completes pending futures");
        assertNull(result[0]);
    }

    // ---- fakes -------------------------------------------------------------------------------

    private interface Fn { Object apply(Object[] args); }

    @SuppressWarnings("unchecked")
    private static <T> T proxy(Class<T> type, Map<String, Fn> impls) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, (p, method, args) -> {
            Fn fn = impls.get(method.getName());
            if (fn != null) return fn.apply(args);
            return switch (method.getName()) {
                case "hashCode" -> System.identityHashCode(p);
                case "equals" -> p == (args != null ? args[0] : null);
                case "toString" -> type.getSimpleName() + "@fake";
                default -> null;
            };
        });
    }

    private interface HttpSend { HttpRequestResponse send(HttpRequest request); }
    private interface EngineFactory { RequestExecutionEngine create(RequestEngineOptions options); }

    private static MontoyaApi fakeApi(BurpSuiteEdition edition, HttpSend httpSend, EngineFactory engineFactory) {
        Version version = proxy(Version.class, Map.of("edition", a -> edition));
        BurpSuite burpSuite = proxy(BurpSuite.class, Map.of("version", a -> version));
        Http http = proxy(Http.class, Map.of(
                "sendRequest", a -> httpSend.send((HttpRequest) a[0]),
                "createRequestEngine", a -> engineFactory.create((RequestEngineOptions) a[0])));
        return proxy(MontoyaApi.class, Map.of("burpSuite", a -> burpSuite, "http", a -> http));
    }
}
