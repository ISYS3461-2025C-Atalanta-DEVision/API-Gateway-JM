package com.devision.jm.gateway.filter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.UUID;

/**
 * Logging Filter
 *
 * Provides centralized request/response logging for observability.
 * Generates correlation IDs for request tracing across microservices.
 */
@Slf4j
@Component
public class LoggingFilter implements GlobalFilter, Ordered {

    private static final String CORRELATION_ID_HEADER = "X-Correlation-Id";
    private static final String REQUEST_TIME_ATTR = "requestTime";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();

        // Generate or extract correlation ID for distributed tracing
        String correlationId = request.getHeaders().getFirst(CORRELATION_ID_HEADER);
        if (correlationId == null || correlationId.isEmpty()) {
            correlationId = UUID.randomUUID().toString();
        }

        // Store request start time
        exchange.getAttributes().put(REQUEST_TIME_ATTR, Instant.now());

        // Add correlation ID to request headers for downstream services
        ServerHttpRequest modifiedRequest = request.mutate()
                .header(CORRELATION_ID_HEADER, correlationId)
                .build();

        // Log incoming request
        log.info("Incoming request: {} {} - CorrelationId: {} - Client: {}",
                request.getMethod(),
                request.getURI().getPath(),
                correlationId,
                getClientInfo(exchange));

        String finalCorrelationId = correlationId;
        return chain.filter(exchange.mutate().request(modifiedRequest).build())
                .then(Mono.fromRunnable(() -> {
                    // Log response
                    Instant requestTime = exchange.getAttribute(REQUEST_TIME_ATTR);
                    long duration = requestTime != null ?
                            Instant.now().toEpochMilli() - requestTime.toEpochMilli() : 0;

                    log.info("Outgoing response: {} {} - Status: {} - Duration: {}ms - CorrelationId: {}",
                            request.getMethod(),
                            request.getURI().getPath(),
                            exchange.getResponse().getStatusCode(),
                            duration,
                            finalCorrelationId);
                }));
    }

    private String getClientInfo(ServerWebExchange exchange) {
        String forwardedFor = exchange.getRequest().getHeaders().getFirst("X-Forwarded-For");
        if (forwardedFor != null && !forwardedFor.isEmpty()) {
            return forwardedFor.split(",")[0].trim();
        }

        var remoteAddress = exchange.getRequest().getRemoteAddress();
        return remoteAddress != null ? remoteAddress.toString() : "unknown";
    }

    @Override
    public int getOrder() {
        // Execute first
        return -3;
    }
}
