package com.devision.jm.gateway.filter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Internal API Key Filter for API Gateway
 *
 * Adds an internal API key header to all requests forwarded to microservices.
 * This ensures that microservices only accept requests from the API Gateway.
 *
 * Security: Microservices validate this header to reject direct external access.
 */
@Slf4j
@Component
public class InternalApiKeyFilter implements GlobalFilter, Ordered {

    public static final String INTERNAL_API_KEY_HEADER = "X-Internal-Api-Key";

    @Value("${internal.api-key}")
    private String internalApiKey;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // Add internal API key to all outgoing requests
        ServerHttpRequest modifiedRequest = exchange.getRequest().mutate()
                .header(INTERNAL_API_KEY_HEADER, internalApiKey)
                .build();

        log.debug("Adding internal API key header to request: {}", exchange.getRequest().getPath());

        return chain.filter(exchange.mutate().request(modifiedRequest).build());
    }

    @Override
    public int getOrder() {
        // Run after authentication filter (-100) to add internal key to validated requests
        return -50;
    }
}
