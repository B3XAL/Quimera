package com.b3xal.headeranalyzer.util;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/** Small, bounded daemon pools used by extension-owned background work. */
public final class BackgroundExecutors {
    private BackgroundExecutors() {}

    public static ExecutorService bounded(String name, int threads, int queueCapacity) {
        return executor(name, threads, queueCapacity, new ThreadPoolExecutor.AbortPolicy());
    }

    /**
     * Bounded executor for analysis that must not be silently lost.  Under ordinary load this is
     * identical to {@link #bounded}; only when both workers and its small queue are occupied does
     * the submitting thread execute the work.  That deliberately applies back-pressure instead
     * of dropping an observed exchange or a probe that was already claimed for execution.
     *
     * Do not use this for arbitrary UI work: callers must be safe to run their task directly.
     */
    public static ExecutorService backpressured(String name, int threads, int queueCapacity) {
        return executor(name, threads, queueCapacity, new ThreadPoolExecutor.CallerRunsPolicy());
    }

    /**
     * Fixed-rate work lane whose jobs have already moved their HTTP payload to Burp temporary
     * storage. It must never run work on the submitting HTTP callback or reject a captured unit;
     * the queue therefore holds only lightweight task references while its bounded worker count
     * controls CPU and network consumption.
     */
    public static ExecutorService lossless(String name, int threads) {
        AtomicInteger sequence = new AtomicInteger();
        return new ThreadPoolExecutor(
                threads, threads, 0L, TimeUnit.MILLISECONDS,
                new LinkedBlockingQueue<>(),
                task -> {
                    Thread thread = new Thread(task, name + "-" + sequence.incrementAndGet());
                    thread.setDaemon(true);
                    return thread;
                },
                new ThreadPoolExecutor.AbortPolicy());
    }

    private static ExecutorService executor(String name, int threads, int queueCapacity,
                                            java.util.concurrent.RejectedExecutionHandler rejectionHandler) {
        AtomicInteger sequence = new AtomicInteger();
        return new ThreadPoolExecutor(
                threads, threads, 0L, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(queueCapacity),
                task -> {
                    Thread thread = new Thread(task, name + "-" + sequence.incrementAndGet());
                    thread.setDaemon(true);
                    return thread;
                },
                rejectionHandler);
    }
}
