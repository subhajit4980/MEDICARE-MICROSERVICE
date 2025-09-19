package com.medicare.Auth_Service.Events;

import jakarta.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;

@Document(collection = "outbox_events")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class OutboxEvent {
    @Id
    private String id;
    private String aggregateId;   // user id
    private String eventType;     // "USER_REGISTERED"
    private String payload;       // JSON
    private Instant createdAt = Instant.now();
    private boolean published = false;
    private int attempts = 0;
}
