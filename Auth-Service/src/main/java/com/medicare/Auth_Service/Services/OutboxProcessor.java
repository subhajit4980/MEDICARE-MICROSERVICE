package com.medicare.Auth_Service.Services;

import com.medicare.Auth_Service.Events.OutboxEvent;
import com.medicare.Auth_Service.Repositories.OutboxRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.concurrent.ExecutionException;

@Service
@RequiredArgsConstructor
public class OutboxProcessor {

    private final OutboxRepository outboxRepository;
    private final KafkaTemplate<String, String> kafkaTemplate;
    @Value("${outbox.processor.batch-size:50}")
    private int batchSize;

    private static final String TOPIC = "user-registered-topic";

    @Scheduled(fixedDelayString = "${outbox.processor.delay-ms:5000}")
    public void process() {
        List<OutboxEvent> events = outboxRepository.findTop50ByPublishedFalseOrderByCreatedAtAsc();
        for (OutboxEvent ev : events) {
            try {
                kafkaTemplate.executeInTransaction(k -> {
                    try {
                        k.send(TOPIC, ev.getAggregateId(), ev.getPayload()).get(); // wait to ensure send
                    } catch (InterruptedException | ExecutionException e) {
                        throw new RuntimeException(e);
                    }
                    return true;
                });
                ev.setPublished(true);
                outboxRepository.save(ev);
            } catch (Exception e) {
                // increment attempts - optional
                ev.setAttempts(ev.getAttempts() + 1);
                outboxRepository.save(ev);
                // log and continue; retries will happen next schedule
            }
        }
    }
}
