package com.b3xal.headeranalyzer.browser;

import com.b3xal.headeranalyzer.model.HeaderFinding;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

/**
 * Test-only entry point: starts just {@link BrowserBridgeServer} against a real
 * {@link com.b3xal.headeranalyzer.config.QuimeraSettings} (no persistence, defaults only) and a
 * minimal {@code MontoyaApi} stand-in, printing every received finding to stdout instead of
 * feeding a (Burp-only) {@code QuimeraTab}. Lets the extension side (content script + background
 * bridge client) be exercised end to end without running Burp Suite at all.
 *
 * The {@code MontoyaApi}/{@code Logging} stand-ins are JDK dynamic proxies rather than hand-written
 * implementations: {@link BrowserBridgeServer} only ever calls {@code api.logging()
 * .logToOutput(String)}/{@code .logToError(String)} in this standalone path, and a hand-rolled
 * class implementing every method on those interfaces would silently drift out of sync with the
 * Montoya API version pinned in {@code build.gradle} (both interfaces have grown methods across
 * releases already). The proxy needs no such maintenance: any unexercised method just throws.
 *
 * Not part of the shipped extension, excluded from the jar's {@code Main-Class} manifest entry,
 * run directly with the same classpath used to build Quimera:
 * <pre>
 *   java -cp build/classes:montoya-api.jar \
 *     com.b3xal.headeranalyzer.browser.BrowserBridgeStandalone
 * </pre>
 * Then load the browser extension, open test/seed.html, and watch findings print here.
 */
public final class BrowserBridgeStandalone {

    private BrowserBridgeStandalone() {}

    public static void main(String[] args) throws Exception {
        var api = loggingOnlyMontoyaApi();
        var settings = new com.b3xal.headeranalyzer.config.QuimeraSettings(); // persistence=null -> defaults
        String token = args.length > 0 ? args[0] : "standalone-test-token-00000000000000000000";
        int port = args.length > 1 ? Integer.parseInt(args[1]) : settings.getBrowserBridgePort();
        settings.setBrowserBridgeToken(token);
        settings.setBrowserBridgePort(port);
        settings.setBrowserBridgeEnabled(true);
        var ruleStore = new com.b3xal.headeranalyzer.analyzer.RuleStore(null);
        var engine = new com.b3xal.headeranalyzer.analyzer.HeaderAnalysisEngine(ruleStore, settings);

        BrowserBridgeServer server = new BrowserBridgeServer(api, settings, engine, result -> {
            System.out.println();
            System.out.println("=== Browser snapshot received: " + result.url + " ===");
            if (result.findings.isEmpty()) {
                System.out.println("(no findings)");
            }
            for (HeaderFinding f : result.findings) {
                System.out.println("[" + f.severity.label + "/" + f.confidence.label + "] " + f.issueName);
                System.out.println("    evidence: " + f.evidence);
            }
        }, () -> new ScopeHostTracker.ScopeSnapshot(
                java.util.List.of("scope.example.test"), java.util.List.of()), false);
        server.start();
        System.out.println("Quimera browser bridge standalone listening on http://127.0.0.1:"
                + settings.getBrowserBridgePort() + "  (Ctrl+C to stop; development only)");
        Thread.currentThread().join(); // keep the JVM alive; the server's own executor does the work
    }

    /** Builds a MontoyaApi proxy whose logging() returns a stdout/stderr-backed Logging proxy, and
     * whose every other method throws if ever called (nothing else in the browser-bridge code path
     * needs one). */
    private static burp.api.montoya.MontoyaApi loggingOnlyMontoyaApi() {
        Object logging = Proxy.newProxyInstance(
                BrowserBridgeStandalone.class.getClassLoader(),
                new Class<?>[] { burp.api.montoya.logging.Logging.class },
                (InvocationHandler) (proxy, method, args) -> {
                    switch (method.getName()) {
                        case "logToOutput" -> System.out.println("[log] " + String.valueOf(args[0]));
                        case "logToError" -> System.err.println("[error] " + String.valueOf(args[0]));
                        case "raiseInfoEvent" -> System.out.println("[info] " + args[0]);
                        case "raiseErrorEvent", "raiseCriticalEvent" -> System.err.println("[event] " + args[0]);
                        default -> { /* debug events etc, no-op */ }
                    }
                    return null;
                });

        return (burp.api.montoya.MontoyaApi) Proxy.newProxyInstance(
                BrowserBridgeStandalone.class.getClassLoader(),
                new Class<?>[] { burp.api.montoya.MontoyaApi.class },
                (InvocationHandler) (proxy, method, args) -> {
                    if ("logging".equals(method.getName())) return logging;
                    throw new UnsupportedOperationException(
                            "BrowserBridgeStandalone stub does not implement MontoyaApi#" + method.getName()
                            + "() (unused by the browser-bridge server in standalone mode)");
                });
    }
}
