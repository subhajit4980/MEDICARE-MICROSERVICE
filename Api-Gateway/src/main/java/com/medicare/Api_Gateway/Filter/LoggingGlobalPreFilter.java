package com.medicare.Api_Gateway.Filter;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
public class LoggingGlobalPreFilter implements GlobalFilter, Ordered {
    private final JwtAuthGatewayFilterFactory jwtAuthGatewayFilterFactory;
    private static final Logger logger = LoggerFactory.getLogger(LoggingGlobalPreFilter.class);

    @Override
    public Mono<Void> filter(org.springframework.web.server.ServerWebExchange exchange,
                             org.springframework.cloud.gateway.filter.GatewayFilterChain chain) {

        ServerHttpRequest request = exchange.getRequest();
        logger.info(">>> Incoming Request: method={}, path={}, headers={}",
                request.getMethod(), request.getURI().getPath(), request.getHeaders());
        return jwtAuthGatewayFilterFactory.apply(new JwtAuthGatewayFilterFactory.Config()).filter(exchange, chain);

//        return chain.filter(exchange);
    }

    // Ensure this runs **before** route-specific filters
    @Override
    public int getOrder() {
        return -1;
    }
}
