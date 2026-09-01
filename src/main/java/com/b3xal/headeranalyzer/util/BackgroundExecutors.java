package com.b3xal.headeranalyzer.util;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/** Small, bounded daemon pools used by extension-owned background work. */
public final class BackgroundExecutors {
    private BackgroundExecutors() {}

    public static ExecutorService bounded(String name, int threads, int queueCapacity) {
        AtomicInteger sequence = new AtomicInteger();
        return new ThreadPoolExecutor(
                threads, threads, 0L, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(queueCapacity),
                task -> {
                    Thread thread = new Thread(task, name + "-" + sequence.incrementAndGet());
                    thread.setDaemon(true);
                    return thread;
                },
                new ThreadPoolExecutor.AbortPolicy());
    }
}
