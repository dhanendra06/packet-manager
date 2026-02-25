package io.mosip.commons.packet.config;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
@Configuration
@EnableAsync
public class AuditConfig {
    // Read values from properties / config-server
    @Value("${mosip.packet.manager.audit.core-pool-size:4}")
    private int corePoolSize;
    @Value("${mosip.packet.manager.audit.max-pool-size:16}")
    private int maxPoolSize;
    @Value("${mosip.packet.manager.audit.queue-capacity:500}")
    private int queueCapacity;
    @Value("${mosip.packet.manager.audit.thread-name-prefix:Audit-}")
    private String threadNamePrefix;
    @Value("${mosip.packet.manager.audit.await-termination-seconds:30}")
    private int awaitTerminationSeconds;
    @Bean(name = "auditExecutor")
    public ThreadPoolTaskExecutor auditExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(corePoolSize);
        executor.setMaxPoolSize(maxPoolSize);
        executor.setQueueCapacity(queueCapacity);
        executor.setThreadNamePrefix(threadNamePrefix);
        // Graceful shutdown: wait for tasks to complete
        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(awaitTerminationSeconds);
        // Optional: rejection policy (what to do when queue is full)
        // executor.setRejectedExecutionHandler(new ThreadPoolExecutor.CallerRunsPolicy());
        executor.initialize();
        return executor;
    }
}