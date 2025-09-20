package com.medicare.Auth_Service.Config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

@Configuration // Tells Spring that this class contains bean definitions (like application config)
public class RedisConfig {

    /**
     * Creates and configures a RedisTemplate bean.
     * RedisTemplate is the main class used to interact with Redis
     * (storing, retrieving, deleting values).
     *
     * @param connectionFactory A RedisConnectionFactory automatically provided by Spring Boot
     *                          (based on your application.properties/yml Redis settings).
     * @return A configured RedisTemplate<String, Object>
     */
    @Bean
    public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory connectionFactory) {
        RedisTemplate<String, Object> template = new RedisTemplate<>();

        // Inject Redis connection (host, port, etc. configured in application.yml/properties).
        template.setConnectionFactory(connectionFactory);

        // --- SERIALIZATION STRATEGY ---
        // Why serializers? Because Redis stores data as raw bytes.
        // Serializers convert Java objects <-> Redis-storable format.

        // ✅ Key serializer
        // All keys will be stored as plain readable strings instead of unreadable binary.
        template.setKeySerializer(new StringRedisSerializer());

        // ✅ Value serializer
        // Values (Objects) will be stored in JSON format using Jackson.
        // Example: a User object -> {"id":1,"name":"Subhajit"}
        template.setValueSerializer(new GenericJackson2JsonRedisSerializer());

        // ✅ Hash key serializer
        // For Redis Hash structures (like a map inside Redis), store field names as plain strings.
        template.setHashKeySerializer(new StringRedisSerializer());

        // ✅ Hash value serializer
        // For values inside Redis Hash, use JSON for readability and portability.
        template.setHashValueSerializer(new GenericJackson2JsonRedisSerializer());

        // Apply all the above settings to RedisTemplate
        template.afterPropertiesSet();

        // Return the fully configured RedisTemplate bean
        return template;
    }
}
