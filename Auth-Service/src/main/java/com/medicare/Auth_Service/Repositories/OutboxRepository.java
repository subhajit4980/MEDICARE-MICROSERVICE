package com.medicare.Auth_Service.Repositories;

import com.medicare.Auth_Service.Events.OutboxEvent;
import org.springframework.data.mongodb.repository.MongoRepository;

import javax.xml.crypto.Data;
import java.time.Instant;
import java.util.Date;
import java.util.List;

public interface OutboxRepository extends MongoRepository<OutboxEvent, String> {
    List<OutboxEvent> findTop50ByPublishedFalseOrderByCreatedAtAsc();
    void deleteByPublishedTrueAndCreatedAtBefore(Instant cutoff);
}
