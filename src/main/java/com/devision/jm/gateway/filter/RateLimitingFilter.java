package com.devision.jm.gateway.filter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.Duration;

/**
 * Rate Limiting Filter
 *
 * Implements rate limiting using Redis to prevent abuse.
 * Supports brute-force attack prevention (Medium 2.2.2).
 *
 * Rate limits:
 * - General API: 100 requests per minute per IP
 * - Login endpoint: 5 requests per minute per IP (brute-force protection)
 */
@Slf4j
@Component
public class RateLimitingFilter implements GlobalFilter, Ordered {

    private static final int GENERAL_RATE_LIMIT = 100;
    private static final int LOGIN_RATE_LIMIT = 5;
    private static final Duration RATE_LIMIT_WINDOW = Duration.ofMinutes(1);
    private static final String RATE_LIMIT_KEY_PREFIX = "rate_limit:";

    private final ReactiveRedisTemplate<String, String> redisTemplate;

    public RateLimitingFilter(ReactiveRedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String clientIp = getClientIp(exchange);
        String path = exchange.getRequest().getURI().getPath();

        // Determine rate limit based on endpoint
        int rateLimit = isLoginEndpoint(path) ? LOGIN_RATE_LIMIT : GENERAL_RATE_LIMIT;
        String rateLimitKey = RATE_LIMIT_KEY_PREFIX + clientIp + ":" + (isLoginEndpoint(path) ? "login" : "general");

        return redisTemplate.opsForValue()
                .increment(rateLimitKey)
                .flatMap(count -> {
                    if (count == 1) {
                        // Set expiration on first request
                        return redisTemplate.expire(rateLimitKey, RATE_LIMIT_WINDOW)
                                .thenReturn(count);
                    }
                    return Mono.just(count);
                })
                .flatMap(count -> {
                    if (count > rateLimit) {
                        log.warn("Rate limit exceeded for IP: {} on path: {}", clientIp, path);
                        exchange.getResponse().setStatusCode(HttpStatus.TOO_MANY_REQUESTS);
                        exchange.getResponse().getHeaders()
                                .add("X-RateLimit-Retry-After", String.valueOf(RATE_LIMIT_WINDOW.getSeconds()));
                        return exchange.getResponse().setComplete();
                    }

                    // Add rate limit headers
                    exchange.getResponse().getHeaders()
                            .add("X-RateLimit-Limit", String.valueOf(rateLimit));
                    exchange.getResponse().getHeaders()
                            .add("X-RateLimit-Remaining", String.valueOf(Math.max(0, rateLimit - count)));

                    return chain.filter(exchange);
                })
                .onErrorResume(e -> {
                    // If Redis is unavailable, allow the request
                    log.error("Rate limiting check failed: {}", e.getMessage());
                    return chain.filter(exchange);
                });
    }

    private String getClientIp(ServerWebExchange exchange) {
        // Check for forwarded IP (when behind a proxy/load balancer)
        String forwardedFor = exchange.getRequest().getHeaders().getFirst("X-Forwarded-For");
        if (forwardedFor != null && !forwardedFor.isEmpty()) {
            return forwardedFor.split(",")[0].trim();
        }

        // Fallback to remote address
        var remoteAddress = exchange.getRequest().getRemoteAddress();
        return remoteAddress != null ? remoteAddress.getAddress().getHostAddress() : "unknown";
    }

    private boolean isLoginEndpoint(String path) {
        return path.contains("/auth/login") || path.contains("/auth/admin/login");
    }

    @Override
    public int getOrder() {
        // Execute before authentication filter
        return -2;
    }
}
