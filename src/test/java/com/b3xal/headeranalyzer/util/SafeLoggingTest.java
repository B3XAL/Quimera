package com.b3xal.headeranalyzer.util;

import burp.api.montoya.MontoyaApi;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

class SafeLoggingTest {
    @Test
    void disposedMontoyaLoggerNeverEscapesIntoBackgroundTask() {
        MontoyaApi disposed = (MontoyaApi) Proxy.newProxyInstance(
                MontoyaApi.class.getClassLoader(), new Class<?>[]{MontoyaApi.class},
                (proxy, method, args) -> {
                    if (method.getName().equals("logging"))
                        throw new NullPointerException("disposed Burp logger");
                    return null;
                });

        assertDoesNotThrow(() -> SafeLogging.error(disposed, "probe failed"));
        assertDoesNotThrow(() -> SafeLogging.output(disposed, "unloaded"));
    }
}
