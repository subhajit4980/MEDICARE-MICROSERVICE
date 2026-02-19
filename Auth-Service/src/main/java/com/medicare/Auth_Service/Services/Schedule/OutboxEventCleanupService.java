package com.medicare.Auth_Service.Services.Schedule;

import com.medicare.Auth_Service.Repositories.OutboxRepository;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

@RequiredArgsConstructor
@Service
public class OutboxEventCleanupService {
    private final OutboxRepository outboxRepository;

    /**
     * Executes once right after the application starts.
     * Ensures no expired outbox events remain in DB from before 7 days.
     */
    @PostConstruct
    public void init() {
        try {
            cleanupPublishedEvents();
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Init cleanup error: " + e.getMessage());
        }
    }

    @Scheduled(cron = "0 0 2 * * ?") // every day at 2 AM
    public void cleanupPublishedEvents() {
        outboxRepository.deleteByPublishedTrueAndCreatedAtBefore(
                Instant.now().minus(7, ChronoUnit.DAYS)
        );
        System.out.println("✅ Events cleanup run completed at: " + new java.util.Date());
    }

}
