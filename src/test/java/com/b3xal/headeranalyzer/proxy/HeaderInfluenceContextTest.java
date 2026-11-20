package com.b3xal.headeranalyzer.proxy;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import java.lang.reflect.Proxy;
import java.util.List;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class HeaderInfluenceContextTest {
    private static HttpHeader header(String name, String value) {
        return (HttpHeader) Proxy.newProxyInstance(HttpHeader.class.getClassLoader(),
                new Class<?>[]{HttpHeader.class}, (p, m, a) -> switch (m.getName()) {
                    case "name" -> name;
                    case "value" -> value;
                    default -> null;
                });
    }
    private static String key(HttpHeader... headers) {
        HttpRequest request = (HttpRequest) Proxy.newProxyInstance(HttpRequest.class.getClassLoader(),
                new Class<?>[]{HttpRequest.class}, (p, m, a) -> switch (m.getName()) {
                    case "method" -> "GET";
                    case "url" -> "https://example.test/page";
                    case "headers" -> List.of(headers);
                    default -> null;
                });
        return QuimeraHttpHandler.headerInfluenceContextKey(request);
    }
    @Test void customContextValuesAreNotCollapsed() {
        assertNotEquals(key(header("X-Tenant", "one")), key(header("X-Tenant", "two")));
        assertFalse(key(header("X-Tenant", "private-value")).contains("private-value"));
    }
    @Test void casingAndOrderBetweenDifferentFieldsDoNotReschedule() {
        assertEquals(key(header("X-Tenant", "one"), header("Accept", "text/html")),
                key(header("accept", "text/html"), header("x-tenant", "one")));
    }
    @Test void duplicateValueOrderRemainsSignificant() {
        assertNotEquals(key(header("X-Tenant", "one"), header("X-Tenant", "two")),
                key(header("X-Tenant", "two"), header("X-Tenant", "one")));
    }
}
