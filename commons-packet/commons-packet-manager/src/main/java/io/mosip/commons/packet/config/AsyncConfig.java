package io.mosip.commons.packet.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.*;

import jakarta.annotation.PreDestroy;

@Configuration
public class AsyncConfig {

    @Value("${packetmanager.audit.thread.pool.size:5}")
    private int auditPoolSize;

    @Value("${packetmanager.fetch.thread.pool.size:40}")
    private int fetchPoolSize;

    // Max burst size for fetch pool. Virtual threads are cheap, so this can be set high.
    // When all core threads are busy, the pool grows up to this limit before CallerRunsPolicy fires.
    @Value("${packetmanager.fetch.max.thread.pool.size:160}")
    private int fetchMaxPoolSize;

    @Value("${packetmanager.fetch.queue.capacity:200}")
    private int fetchQueueCapacity;

    @Value("${packetmanager.audit.thread.queue.capacity:50}")
    private int auditQueueCapacity;

    @Value("${packetmanager.validate.thread.pool.size:30}")
    private int validatePoolSize;

    // Max burst size for validate pool.
    @Value("${packetmanager.validate.max.thread.pool.size:100}")
    private int validateMaxPoolSize;

    @Value("${packetmanager.validate.queue.capacity:150}")
    private int validateQueueCapacity;

    // Idle burst threads are reclaimed after this many seconds of inactivity.
    @Value("${packetmanager.thread.keep.alive.seconds:60}")
    private int keepAliveSeconds;

    private ExecutorService auditPool;
    private ExecutorService fetchPool;
    private ExecutorService validatePool;

    /**
     * Fixed platform-thread pool for fire-and-forget audit HTTP calls.
     */
    @Bean(name = "auditTaskExecutor")
    public ExecutorService auditTaskExecutor() {
        auditPool = new ThreadPoolExecutor(
                auditPoolSize,
                auditPoolSize,
                0L, TimeUnit.MILLISECONDS,
                new LinkedBlockingQueue<>(auditQueueCapacity),
                Thread.ofPlatform().name("pkt-audit-", 0).factory(),
                new ThreadPoolExecutor.CallerRunsPolicy());
        return auditPool;
    }

    /**
     * Virtual-thread pool for parallel sub-packet S3 fetches (reads).
     *
     * Virtual threads (Java 21+): when a virtual thread blocks on an S3 / keymanager HTTP call,
     * the underlying carrier (platform) thread is unmounted and freed — Tomcat threads are never
     * starved by I/O waits. The pool can burst from fetchPoolSize (core) up to fetchMaxPoolSize
     * before CallerRunsPolicy fires, giving substantial headroom under load.
     *
     * Tune via:
     *   packetmanager.fetch.thread.pool.size        (default  40)  — core concurrent S3 fetches
     *   packetmanager.fetch.max.thread.pool.size    (default 200)  — max burst size
     *   packetmanager.fetch.queue.capacity          (default 200)  — queue before burst threads spin up
     *   packetmanager.thread.keep.alive.seconds     (default  60)  — idle burst-thread TTL
     */
/*    @Bean(name = "packetFetchExecutor")
    public ExecutorService packetFetchExecutor() {
        fetchPool = new ThreadPoolExecutor(
                fetchPoolSize,
                fetchMaxPoolSize,
                keepAliveSeconds, TimeUnit.SECONDS,
                new ArrayBlockingQueue<>(fetchQueueCapacity),
                Thread.ofVirtual().name("pkt-fetch-", 0).factory(),
                new ThreadPoolExecutor.CallerRunsPolicy());
        return fetchPool;
    }*/
    @Bean(name = "packetFetchExecutor")
    public ExecutorService packetFetchExecutor() {
        fetchPool = Executors.newVirtualThreadPerTaskExecutor();
        return fetchPool;
    }
    /**
     * Virtual-thread pool for parallel sub-packet S3 fetches during validation.
     * Separate from packetFetchExecutor so validate concurrency can be tuned independently.
     *
     * Tune via:
     *   packetmanager.validate.thread.pool.size      (default  30) — core concurrent validate fetches
     *   packetmanager.validate.max.thread.pool.size  (default 150) — max burst size
     *   packetmanager.validate.queue.capacity        (default 150) — queue before burst threads spin up
     *   packetmanager.thread.keep.alive.seconds      (default  60) — idle burst-thread TTL
     */
/*    @Bean(name = "packetValidateExecutor")
    public ExecutorService packetValidateExecutor() {
        validatePool = new ThreadPoolExecutor(
                validatePoolSize,
                validateMaxPoolSize,
                keepAliveSeconds, TimeUnit.SECONDS,
                new ArrayBlockingQueue<>(validateQueueCapacity),
                Thread.ofVirtual().name("pkt-validate-", 0).factory(),
                new ThreadPoolExecutor.CallerRunsPolicy());
        return validatePool;
    }*/

    @PreDestroy
    public void shutdown() {
        if (auditPool != null) {
            auditPool.shutdown();
            try {
                if (!auditPool.awaitTermination(30, TimeUnit.SECONDS))
                    auditPool.shutdownNow();
            } catch (InterruptedException e) {
                auditPool.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }

        // Fetch: graceful — let in-progress S3 downloads complete (up to 30s),
        // then force-stop anything still running
        if (fetchPool != null) {
            fetchPool.shutdown();
            try {
                if (!fetchPool.awaitTermination(30, TimeUnit.SECONDS))
                    fetchPool.shutdownNow();
            } catch (InterruptedException e) {
                fetchPool.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }

        if (validatePool != null) {
            validatePool.shutdown();
            try {
                if (!validatePool.awaitTermination(30, TimeUnit.SECONDS))
                    validatePool.shutdownNow();
            } catch (InterruptedException e) {
                validatePool.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
    }

}
