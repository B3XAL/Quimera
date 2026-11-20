package com.b3xal.headeranalyzer.analyzer;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.burpsuite.BurpSuite;
import burp.api.montoya.core.BurpSuiteEdition;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Version;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.b3xal.headeranalyzer.config.QuimeraSettings;
import com.b3xal.headeranalyzer.model.UrlAnalysisResult;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Exercises the complete Origin battery through its request sender, not only its header matcher. */
class CorsProbeBatteryIntegrationTest {

    @Test
    void sendsAndConfirmsEveryCorsOriginVariantAgainstAnEligibleGet() {
        List<String> originsSent = new ArrayList<>();
        MontoyaApi api = fakeApi(request -> {
            String origin = request.header("Origin").value();
            originsSent.add(origin);
            return exchange(request, origin);
        });
        QuimeraSettings settings = new QuimeraSettings();
        settings.setActiveScanTraceProbe(false);
        settings.setActiveScanHstsProbe(false);
        settings.setActiveScanWebDavProbe(false);

        ActiveHeaderScanner scanner = new ActiveHeaderScanner(api,
                new HeaderAnalysisEngine(new RuleStore(null), settings), settings);
        List<UrlAnalysisResult> results = scanner.scanNonCacheProbes(
                "https://api.example.test/account", request(Map.of()));

        assertEquals(List.of(
                "https://quimera-cors-probe.invalid",
                "http://api.example.test",
                "null",
                "https://api.example.test.quimera-cors-probe.invalid",
                "https://api.example.testquimera-cors-probe.invalid",
                "https://random-quimera.api.example.test",
                "https://api.example.tes",
                "https://apixexample.test",
                "https://api.example.test_quimera-cors-probe.invalid"), originsSent);
        assertEquals(9, results.size());
        assertTrue(results.stream().allMatch(r -> r.findings.size() == 1));
        assertTrue(results.stream().allMatch(r -> r.findings.get(0).issueName.contains("credentials allowed")));
        scanner.shutdown();
    }

    private static HttpRequestResponse exchange(HttpRequest request, String origin) {
        HttpResponse response = proxy(HttpResponse.class, Map.of(
                "headers", ignored -> List.of(header("Access-Control-Allow-Origin", origin),
                        header("Access-Control-Allow-Credentials", "true")),
                "statusCode", ignored -> (short) 200,
                "body", ignored -> proxy(ByteArray.class, Map.of("length", unused -> 2)),
                "toString", ignored -> "HTTP/2 200"));
        return proxy(HttpRequestResponse.class, Map.of(
                "request", ignored -> request,
                "response", ignored -> response));
    }

    private static HttpRequest request(Map<String, String> headers) {
        Map<String, String> values = new LinkedHashMap<>(headers);
        return proxy(HttpRequest.class, Map.of(
                "header", args -> {
                    String value = values.get(args[0]);
                    return value == null ? null : header((String) args[0], value);
                },
                "withHeader", args -> {
                    Map<String, String> copy = new LinkedHashMap<>(values);
                    copy.put((String) args[0], (String) args[1]);
                    return request(copy);
                },
                // ThrottledRequestSender adds its marker using this method; it must not remove Origin.
                "withUpdatedHeader", args -> request(values),
                "method", args -> "GET",
                "toString", args -> "GET /account HTTP/2"));
    }

    private static HttpHeader header(String name, String value) {
        return proxy(HttpHeader.class, Map.of(
                "name", ignored -> name,
                "value", ignored -> value,
                "toString", ignored -> name + ": " + value));
    }

    private static MontoyaApi fakeApi(java.util.function.Function<HttpRequest, HttpRequestResponse> send) {
        Http http = proxy(Http.class, Map.of("sendRequest", args -> send.apply((HttpRequest) args[0])));
        Version version = proxy(Version.class, Map.of("edition", ignored -> BurpSuiteEdition.COMMUNITY_EDITION));
        BurpSuite burpSuite = proxy(BurpSuite.class, Map.of("version", ignored -> version));
        return proxy(MontoyaApi.class, Map.of("http", ignored -> http, "burpSuite", ignored -> burpSuite));
    }

    private interface Invocation { Object call(Object[] arguments); }

    @SuppressWarnings("unchecked")
    private static <T> T proxy(Class<T> type, Map<String, Invocation> methods) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, (instance, method, arguments) -> {
            Invocation implementation = methods.get(method.getName());
            if (implementation != null) return implementation.call(arguments == null ? new Object[0] : arguments);
            return switch (method.getName()) {
                case "hashCode" -> System.identityHashCode(instance);
                case "equals" -> instance == (arguments == null ? null : arguments[0]);
                case "toString" -> type.getSimpleName() + "@test";
                default -> null;
            };
        });
    }
}
