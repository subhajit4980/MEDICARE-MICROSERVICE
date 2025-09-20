package com.medicare.Auth_Service.Config;

import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.serialization.StringSerializer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.annotation.EnableKafka;
import org.springframework.kafka.core.DefaultKafkaProducerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.core.ProducerFactory;
import org.springframework.kafka.transaction.KafkaTransactionManager;

import java.util.HashMap;
import java.util.Map;

@Configuration          // Marks this class as a Spring config class
@EnableKafka            // Enables Kafka support in Spring Boot
public class KafkaProducerConfig {

    // Inject Kafka broker address from application.yml
    @Value("${spring.kafka.bootstrap-servers}")
    private String bootstrapServers;

    /**
     * ProducerFactory -> Creates Kafka producers with specific configs
     */
    @Bean
    public ProducerFactory<String, String> producerFactory() {
        Map<String, Object> props = new HashMap<>();
        // Where Kafka cluster is running (ex: localhost:9092)
        props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);

        // Kafka expects Key and Value serializers (convert Java → bytes)
        props.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
        props.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer.class);

        // "all" means producer waits for full acknowledgement (leader + replicas)
        props.put(ProducerConfig.ACKS_CONFIG, "all");

        // Transaction ID is REQUIRED for transactional producers
        // (must be unique per producer instance)
        props.put(ProducerConfig.TRANSACTIONAL_ID_CONFIG, "tx-1");

        // Enables idempotence (guarantees no duplicate messages on retries)
        props.put(ProducerConfig.ENABLE_IDEMPOTENCE_CONFIG, true);

        return new DefaultKafkaProducerFactory<>(props);
    }

    /**
     * KafkaTemplate -> Abstraction to send messages easily
     */
    @Bean
    public KafkaTemplate<String, String> kafkaTemplate() {
        return new KafkaTemplate<>(producerFactory());
    }

    /**
     * KafkaTransactionManager -> Integrates Kafka transactions with Spring
     * Used when you want to send messages inside @Transactional methods
     */
    @Bean
    public KafkaTransactionManager<String, String> kafkaTransactionManager(
            ProducerFactory<String, String> producerFactory) {
        return new KafkaTransactionManager<>(producerFactory);
    }
}
