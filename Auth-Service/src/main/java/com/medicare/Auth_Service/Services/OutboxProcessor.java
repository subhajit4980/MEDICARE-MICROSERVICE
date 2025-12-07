package com.medicare.Auth_Service.Services;

import com.medicare.Auth_Service.Events.OutboxEvent;
import com.medicare.Auth_Service.Repositories.OutboxRepository;
import com.medicare.Auth_Service.Exception.UserException;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.concurrent.ExecutionException;

@Service
@RequiredArgsConstructor
public class OutboxProcessor {

    private static final Logger log = LoggerFactory.getLogger(OutboxProcessor.class);

    private final OutboxRepository outboxRepository;
    private final KafkaTemplate<String, String> kafkaTemplate;
    @Value("${outbox.processor.batch-size:50}")
    private int batchSize;

    private static final String TOPIC = "user-registered-topic";

    @Scheduled(fixedDelayString = "${outbox.processor.delay-ms:5000}")
    public void process() {
        // fetch up to configured batch size (repository method used in original code returned 50)
        List<OutboxEvent> events = outboxRepository.findTop50ByPublishedFalseOrderByCreatedAtAsc();
        for (OutboxEvent ev : events) {
            try {
                // Run the kafka send inside a transaction so the send and outbox updates can be coordinated
                kafkaTemplate.executeInTransaction(k -> {
                    try {
                        // send and wait to ensure send completed
                        k.send(TOPIC, ev.getAggregateId(), ev.getPayload()).get();
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        throw new UserException(HttpStatus.INTERNAL_SERVER_ERROR, "Kafka send interrupted", "AUTH_OUTBOX_KAFKA_INTERRUPTED");
                    } catch (ExecutionException ee) {
                        throw new UserException(HttpStatus.INTERNAL_SERVER_ERROR, "Kafka send failed: " + ee.getCause(), "AUTH_OUTBOX_KAFKA_SEND_ERROR");
                    }
                    return true;
                });

                // mark published and persist
                ev.setPublished(true);
                outboxRepository.save(ev);
            } catch (UserException ue) {
                // Domain-specific exception from above; increment attempts and persist, log details
                ev.setAttempts(ev.getAttempts() + 1);
                outboxRepository.save(ev);
                log.error("Outbox event processing failed (domain): aggregateId={}, attempts={}, errorCode={}, message={}",
                        ev.getAggregateId(), ev.getAttempts(), ue.getErrorCode(), ue.getMessage());
                // continue – will retry in next schedule
            } catch (Exception e) {
                // Non-domain unexpected exception: record attempt and persist, but do not leak internal exception to callers.
                ev.setAttempts(ev.getAttempts() + 1);
                outboxRepository.save(ev);
                log.error("Outbox event processing failed (unexpected): aggregateId={}, attempts={}, cause={}",
                        ev.getAggregateId(), ev.getAttempts(), e.toString(), e);
                // continue; retries will happen next schedule
            }
        }
    }
}
