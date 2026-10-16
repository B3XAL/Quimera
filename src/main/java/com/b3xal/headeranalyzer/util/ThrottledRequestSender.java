package com.b3xal.headeranalyzer.util;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.BurpSuiteEdition;
import burp.api.montoya.http.execution.RequestEngineOptions;
import burp.api.montoya.http.execution.RequestExecution;
import burp.api.montoya.http.execution.RequestExecutionEngine;
import burp.api.montoya.http.execution.RequestResult;
import burp.api.montoya.http.execution.ResourcePool;
import burp.api.montoya.http.execution.Retention;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.time.Duration;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Sends every active-probe request through the SAME resource pool Burp's own Scanner and Live
 * Tasks draw on (Project options / Resource Pool / "Default"), via Montoya's
 * {@link RequestExecutionEngine} bound to {@link ResourcePool#defaultResourcePool()}, instead of
 * firing at whatever rate Quimera's own internal thread pools happen to allow.
 *
 * {@code createRequestEngine} is Professional-only, so on Community Edition (or if engine
 * creation fails for any other reason) this transparently falls back to a plain
 * {@code api.http().sendRequest(...)} call, i.e. Quimera's original, unthrottled behaviour there,
 * never a hard failure.
 *
 * DISABLED (see {@link #send}, which never attempts the engine at all): TWO different
 * Montoya-documented usage patterns were tried and BOTH confirmed, live, to hang forever.
 * Attempt 1 used a custom {@code RequestSource} pulled from lazily ("streaming, for very large
 * runs"): {@code engine.sendAll(RequestSource, ResponseHandler)} itself never returned, twice,
 * independently. Attempt 2 switched to the "reactive" shape instead (seed {@code engine.queue()},
 * then {@code sendAll(ResponseHandler)}, later requests via {@code RequestExecution.queue()}
 * directly, no custom RequestSource at all): identical failure, every single active-probe request
 * timed out waiting on it. Two structurally different official patterns failing the same way is
 * strong evidence the problem is in {@code RequestExecutionEngine}/{@code ResourcePool
 * .defaultResourcePool()} itself on this Burp install (a brand new API, introduced 2026.7, ~2
 * months old at the time of writing), not in how this class calls it. Worth reporting to
 * PortSwigger; not worth a third live retry without new information. The queue/timeout/shutdown
 * plumbing below is left in place and still exercised by {@code ThrottledRequestSenderTest} via
 * the test-only constructor, ready for a future attempt once there's an actual root cause.
 */
public final class ThrottledRequestSender {
    public static final String MARKER_HEADER = "X-Quimera-Internal-Probe";

    /*
     * RequestExecutionEngine is currently disabled because of the documented Burp hang above.
     * A shared gate keeps the direct-send fallback from turning the independent probe lanes into
     * a burst generator.  It is process-wide for this extension class loader, hence covers
     * headers, JWT, session replay, Google-key verification and header-influence probes alike.
     */
    // Five probe requests per second globally. Individual probe families can impose a larger
    // delay (for example HeaderInfluenceProbe's configurable 333 ms catalogue pacing).
    private static final long GLOBAL_DIRECT_SEND_INTERVAL_NANOS = TimeUnit.MILLISECONDS.toNanos(200);
    private static final Object GLOBAL_DIRECT_SEND_LOCK = new Object();
    private static long nextDirectSendNanos;

    private static final Duration ENGINE_TIMEOUT = Duration.ofSeconds(60);

    private final MontoyaApi api;
    private final String dashboardTaskName;
    private final Map<String, CompletableFuture<HttpRequestResponse>> pending = new ConcurrentHashMap<>();
    private volatile boolean shuttingDown = false;
    // Do not keep calling a Montoya HTTP proxy after it has gone null during a Burp reload.
    // Besides wasting workers, every attempt used to trigger a second failure in Burp's logger.
    private final AtomicBoolean apiUnavailable = new AtomicBoolean(false);

    // Single dedicated thread for the one-time "create the engine, seed it, start its run"
    // sequence: isolates a hang inside engine.sendAll(...) to this one thread, never blocking the
    // synchronized section below or any send() caller beyond its own ENGINE_TIMEOUT wait.
    private final ExecutorService initExecutor = BackgroundExecutors.bounded(
            "Quimera-EngineInit", 1, 4);
    private final Object initLock = new Object();
    private CompletableFuture<RequestExecution> engineReady; // null until the first real send() call
    private volatile RequestExecution execution; // set once engineReady completes successfully; used by shutdown()

    public ThrottledRequestSender(MontoyaApi api, String dashboardTaskName) {
        this.api = api;
        this.dashboardTaskName = dashboardTaskName;
    }

    /** Test-only seam: wires an already-"running" execution directly, skipping Community Edition
     * detection and the real (live-Burp-only) engine/seed/sendAll sequence entirely. */
    ThrottledRequestSender(MontoyaApi api, RequestExecution testExecution) {
        this.api = api;
        this.dashboardTaskName = "test";
        this.engineReady = CompletableFuture.completedFuture(testExecution);
        this.execution = testExecution;
    }

    /** Runs once, on {@link #initExecutor}: creates the engine, queues {@code seedRequest} as its
     * very first item, then starts the run. Never called on the same thread as any {@link #send}
     * caller, see the class javadoc for why. */
    private void startEngine(HttpRequest seedRequest, String seedId, CompletableFuture<RequestExecution> ready) {
        try {
            if (api.burpSuite().version().edition() == BurpSuiteEdition.COMMUNITY_EDITION) {
                ready.complete(null);
                return;
            }
            RequestEngineOptions options = RequestEngineOptions.requestEngineOptions()
                    .withName(dashboardTaskName)
                    .withResourcePool(ResourcePool.defaultResourcePool());
            RequestExecutionEngine engine = api.http().createRequestEngine(options);
            engine.queue(seedRequest, seedId);
            RequestExecution started = engine.sendAll(this::onResponse);
            execution = started;
            ready.complete(started);
        } catch (Throwable e) {
            // Deliberately catches Throwable, not just RuntimeException/Exception: this class
            // exists purely to add optional throttling on top of a fully-working direct-send
            // fallback, so no failure here, of any kind, may be allowed to escape.
            SafeLogging.output(api, "Quimera: project resource pool unavailable for '" + dashboardTaskName
                    + "' (" + e + "), sending its probes unthrottled instead.");
            ready.complete(null);
        }
    }

    private Retention onResponse(RequestResult result, RequestExecution liveExecution) {
        CompletableFuture<HttpRequestResponse> future = pending.remove(result.label());
        if (future != null) future.complete(result.requestResponse());
        return Retention.DROP;
    }

    /** Every fallback path in {@link #send} routes through here instead of calling
     * {@code api.http().sendRequest(...)} directly: confirmed live that it can itself throw an
     * uncaught NullPointerException (Burp's own HTTP accessor transiently returning null,
     * presumably mid-reload), which previously escaped this class entirely and killed whichever
     * probe task called it. Same defensive shape as {@link SafeLogging}, applied to sending
     * instead of logging. */
    private HttpRequestResponse directSend(HttpRequest request) {
        if (shuttingDown || apiUnavailable.get()) return null;
        try {
            awaitGlobalDirectSendSlot();
            if (shuttingDown || apiUnavailable.get()) return null;
            return api.http().sendRequest(request);
        } catch (InterruptedException interrupted) {
            // Cancellation/unload is not an API failure.  In particular, do not permanently
            // disable this sender just because a paced worker was interrupted while waiting.
            Thread.currentThread().interrupt();
            return null;
        } catch (Throwable e) {
            apiUnavailable.set(true);
            // Do not globally disable logging here: this may be a transient active-transport
            // failure, and suppressing every subsequent diagnostic hides unrelated passive
            // analysis failures for the rest of the session.
            return null;
        }
    }

    /** Wait outside Burp's HTTP callback in normal operation (all probes use background lanes).
     * The wait is interruptible so extension unload never leaves a worker parked here. */
    private void awaitGlobalDirectSendSlot() throws InterruptedException {
        synchronized (GLOBAL_DIRECT_SEND_LOCK) {
            for (;;) {
                long remaining = nextDirectSendNanos - System.nanoTime();
                if (remaining <= 0) {
                    nextDirectSendNanos = System.nanoTime() + GLOBAL_DIRECT_SEND_INTERVAL_NANOS;
                    return;
                }
                TimeUnit.NANOSECONDS.timedWait(GLOBAL_DIRECT_SEND_LOCK, remaining);
                if (shuttingDown) throw new InterruptedException("Quimera is shutting down");
            }
        }
    }

    /** Sends one request, same contract as {@code api.http().sendRequest(request)}. Always a
     * direct send while the engine is disabled, see the class javadoc. The queue/engine machinery
     * below ({@code isFirst}/{@code engineReady}/{@code exec.queue(...)}) is only reachable via
     * the package-private test constructor, kept working for a future re-enable attempt. */
    public HttpRequestResponse send(HttpRequest request) {
        return sendMarked(request.withUpdatedHeader(MARKER_HEADER, "1"));
    }

    /** Analyst-requested baseline: avoid duplicate live analysis, but permit explicit Retest/Analyze. */
    public HttpRequestResponse sendBaseline(HttpRequest request) {
        return sendMarked(request.withUpdatedHeader(MARKER_HEADER, "baseline"));
    }

    private HttpRequestResponse sendMarked(HttpRequest request) {
        if (shuttingDown || apiUnavailable.get()) return null;
        if (engineReady == null) {
            return directSend(request);
        }
        String id = UUID.randomUUID().toString();
        CompletableFuture<HttpRequestResponse> future = new CompletableFuture<>();
        pending.put(id, future);

        boolean isFirst;
        CompletableFuture<RequestExecution> ready;
        synchronized (initLock) {
            isFirst = engineReady == null;
            if (isFirst) engineReady = new CompletableFuture<>();
            ready = engineReady;
        }

        if (isFirst) {
            try {
                initExecutor.submit(() -> startEngine(request, id, ready));
            } catch (java.util.concurrent.RejectedExecutionException rejected) {
                ready.complete(null);
            }
        }

        // Every caller, first or not, waits here, bounded by ENGINE_TIMEOUT: a quick failure
        // (Community Edition, engine creation throwing) falls back immediately instead of paying
        // the full timeout, and only a genuinely hung sendAll(...) (the confirmed failure mode)
        // costs the full wait before falling back.
        RequestExecution exec;
        try {
            exec = ready.get(ENGINE_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);
        } catch (Exception e) {
            exec = null;
        }
        if (exec == null || shuttingDown) {
            pending.remove(id);
            return directSend(request);
        }
        if (!isFirst) {
            // The first caller's request was already queued as the seed inside startEngine,
            // before sendAll was even called; only later callers queue directly here.
            try {
                exec.queue(request, id);
            } catch (Exception e) {
                // Most likely the run already drained/finished (Montoya: "drains naturally once
                // queuing stops"); this simple design does not start a fresh run after the first
                // one closes, callers just fall back to a direct send from here on.
                pending.remove(id);
                return directSend(request);
            }
        }

        try {
            return future.get(ENGINE_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);
        } catch (TimeoutException te) {
            SafeLogging.error(api, "Quimera: resource pool request for '" + dashboardTaskName
                    + "' did not complete within " + ENGINE_TIMEOUT.getSeconds()
                    + "s, sending this one request directly instead.");
            return directSend(request);
        } catch (Exception e) {
            return null;
        } finally {
            pending.remove(id);
        }
    }

    /** Called from the owning probe class's own shutdown() on extension unload/reload. */
    public void shutdown() {
        shuttingDown = true;
        initExecutor.shutdownNow();
        RequestExecution activeExecution = execution;
        if (activeExecution != null) activeExecution.lifetime().cancel();
        pending.values().forEach(f -> f.complete(null));
        pending.clear();
    }
}
