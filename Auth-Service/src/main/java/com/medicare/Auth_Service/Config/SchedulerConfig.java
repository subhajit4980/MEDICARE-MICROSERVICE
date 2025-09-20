package com.medicare.Auth_Service.Config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;

@Configuration // Marks this as a Spring configuration class
public class SchedulerConfig {

    @Bean // Exposes a ThreadPoolTaskScheduler bean to the Spring context
    public ThreadPoolTaskScheduler taskScheduler() {
        ThreadPoolTaskScheduler scheduler = new ThreadPoolTaskScheduler();

        // Number of threads in the scheduler's pool
        // → up to 5 tasks can run concurrently
        scheduler.setPoolSize(5);

        // Prefix for thread names (helps in logs/monitoring)
        // → Threads will look like "scheduler-1", "scheduler-2", etc.
        scheduler.setThreadNamePrefix("scheduler-");

        // Ensures Spring waits for scheduled tasks to finish before shutting down
        scheduler.setWaitForTasksToCompleteOnShutdown(true);

        // Maximum time (in seconds) to wait for tasks to complete during shutdown
        scheduler.setAwaitTerminationSeconds(30);

        // Handles uncaught exceptions thrown by scheduled tasks
        // → prevents silent failures
        scheduler.setErrorHandler(t ->
                System.err.println("Error in scheduled task: " + t.getMessage())
        );

        return scheduler;
    }
}
