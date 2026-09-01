package com.b3xal.headeranalyzer.util;

import burp.api.montoya.MontoyaApi;

/** Prevents an already-disposed Montoya logger from turning error reporting into another error. */
public final class SafeLogging {
    private SafeLogging() {}

    public static void error(MontoyaApi api, String message) {
        try {
            if (api != null && api.logging() != null) api.logging().logToError(message);
        } catch (Throwable ignored) {
            // In-flight work can finish just after Burp disposes the API during extension reload.
        }
    }

    public static void output(MontoyaApi api, String message) {
        try {
            if (api != null && api.logging() != null) api.logging().logToOutput(message);
        } catch (Throwable ignored) {
            // The extension is already unloading; there is nowhere valid left to log.
        }
    }
}
