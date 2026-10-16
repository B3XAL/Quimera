# Contributing

Use Java 17 or newer and the checked-in Gradle wrapper. Before opening a pull request run:

```bash
./gradlew clean test build
```

Keep the Montoya API as `compileOnly`; it must not be bundled in the release JAR. New detection
rules need tests, a concrete security rationale, bounded input handling and false-positive notes.
Network-active behavior must be off by default, visibly labelled and restricted to the user's
chosen scope. New threads/resources must be closed from the registered unload handler. Do not add
telemetry, remote code, hidden network calls or secrets to the repository.

## BApp Store acceptance criteria

Quimera targets the official PortSwigger BApp Store, whose acceptance criteria are a hard
constraint on every change, not just something checked once before a release. Verify against the
live page before relying on this list for anything security-critical, it can change:
https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating/bapp-store-acceptance-criteria

1. **Unique function**: don't duplicate an existing BApp's function.
2. **Clear, descriptive name**: the name and summary must actually describe what it does.
3. **Secure operation**: treat every HTTP message as untrusted input.
4. **Include all dependencies**: the release artifact must be usable as-is, no missing jars.
5. **Use threads for responsiveness**: never do slow work on the Swing EDT or inside a proxy/
   HTTP handler callback (`HttpHandler`, `ProxyHttpRequestHandler`, `ProxyHttpResponseHandler`,
   `ScanCheck.passiveAudit()`); protect shared state with locks and avoid deadlocks. This is the
   one Quimera has actually regressed on before, twice: once with `ResultStore.persist()` running
   inline on the HTTP handler thread, and once (2026-09) with the ENTIRE per-response passive
   analysis (headers, cookies, credential/leak scanning, and every probe it can trigger) running
   inline too, both confirmed live to visibly delay ordinary browsing on an asset-heavy page before
   being fixed. `handleHttpResponseReceived`/`handleHttpRequestToBeSent` must only ever do cheap,
   near-instant bookkeeping (dedup checks, map/set updates) before returning; anything else goes
   through a dedicated executor.
6. **Unload cleanly**: every thread pool and background resource must be stopped from the
   registered unload handler, with no exceptions. When adding a new `ExecutorService` anywhere,
   add its `shutdownNow()` call to the owning class's `shutdown()` in the same change, and make
   sure that `shutdown()` is actually reachable from `HeaderAnalyzerExtension`'s unload handler
   chain (`QuimeraHttpHandler.shutdown()` and friends), not just defined and never called.
7. **Use Burp's own networking**: send requests via `MontoyaApi.http()`, never a raw
   `HttpURLConnection`/socket/third-party HTTP client, and never issue a request from
   `ScanCheck.passiveAudit()`.
8. **Support offline working**: an extension that depends on an online service/definitions
   (credential-provider metadata, vendor detection signatures) should still be useful without
   network access to that service; don't make basic detection silently depend on live external
   calls succeeding.
9. **Cope with large projects**: never hold a long-term reference to an `HttpRequest`/
   `HttpResponse`/`HttpRequestResponse` object (a short-lived reference for the duration of one
   background task's own processing is fine); be deliberate about anything touching
   `SiteMap.requestResponses()` or a full proxy history.
10. **Provide a parent for GUI elements**: every window/dialog Quimera creates must be a child of
    Burp's own suite frame, not a standalone top-level window.
11. **Use the montoya-api artifact**: declared as a real Gradle/Maven dependency, not vendored.
12. **Burp AI as the default provider**: any AI-enabled feature must default to Burp's own AI
    integration and follow its documented best practices.

