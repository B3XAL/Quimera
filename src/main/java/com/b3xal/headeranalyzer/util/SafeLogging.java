package com.b3xal.headeranalyzer.util;

import burp.api.montoya.MontoyaApi;
import java.util.concurrent.atomic.AtomicBoolean;

/** Prevents an already-disposed Montoya logger from turning error reporting into another error. */
public final class SafeLogging {
    private SafeLogging() {}
    // This is set only by the extension's explicit unload path. A transient Burp logging failure
    // must not black-hole every later diagnostic: that made a real analysis failure look exactly
    // like "nothing happened" for the remainder of a live session.
    private static final AtomicBoolean disabled = new AtomicBoolean(false);

    // Set once at extension load so static, api-less call sites (e.g. cached-regex failures deep in
    // the analysis engine) can still report through Burp's own error stream instead of System.err,
    // which the BApp Store forbids.
    private static volatile MontoyaApi sharedApi;

    /** Registers the Montoya API for api-less call sites. Called once from the extension entry point. */
    public static void init(MontoyaApi api) { sharedApi = api; }

    /** Used by callers that have already established the Montoya API is unavailable. */
    public static void disable() { disabled.set(true); }

    /** Logs to Burp's error stream using the shared API registered at load time. */
    public static void error(String message) { error(sharedApi, message); }

    /** Logs to Burp's output stream using the shared API registered at load time. */
    public static void output(String message) { output(sharedApi, message); }

    public static void error(MontoyaApi api, String message) {
        if (disabled.get()) return;
        try {
            if (api != null && api.logging() != null) api.logging().logToError(message);
        } catch (Throwable ignored) {
            // Burp can transiently dispose its logger while a task unwinds. Do not turn that one
            // failed write into permanent silence; explicit shutdown calls disable() above.
        }
    }

    public static void output(MontoyaApi api, String message) {
        if (disabled.get()) return;
        try {
            if (api != null && api.logging() != null) api.logging().logToOutput(message);
        } catch (Throwable ignored) {
            // See error(): a transient logger failure is not proof this extension is unloaded.
        }
    }
}
