package com.devision.jm.gateway.filter;

/*
 * ============================================================================
 * RATE LIMITING FILTER - CODE FLOW
 * ============================================================================
 *
 * This filter prevents abuse and brute-force attacks (Requirement 2.2.2).
 *
 *   REQUEST COMES IN
 *         │
 *         ▼
 *   ┌─────────────────────────────────────┐
 *   │ 1. Is this a login endpoint?        │
 *   │    - /auth/login                    │
 *   │    - /auth/admin/login              │
 *   └─────────────────────────────────────┘
 *         │ YES                    │ NO
 *         ▼                        ▼
 *   ┌─────────────────┐    ┌─────────────────────────┐
 *   │ LOGIN FLOW      │    │ GENERAL RATE LIMIT      │
 *   │ (by account)    │    │ (by IP address)         │
 *   └─────────────────┘    └─────────────────────────┘
 *         │                        │
 *         ▼                        ▼
 *   ┌─────────────────────────────────────┐
 *   │ 2. Get email from request           │
 *   │    - Check query params             │
 *   │    - If not found, proceed          │
 *   └─────────────────────────────────────┘
 *         │
 *         ▼
 *   ┌─────────────────────────────────────┐
 *   │ 3. Check Redis for failed attempts  │
 *   │    Key: "login_failed:{email}"      │
 *   └─────────────────────────────────────┘
 *         │
 *         ▼
 *   ┌─────────────────────────────────────┐
 *   │ 4. Is account blocked?              │
 *   │    - 5+ failed attempts in 60 sec?  │
 *   └─────────────────────────────────────┘
 *         │ YES → 429 Too Many Requests
 *         │ NO
 *         ▼
 *   FORWARD TO AUTH SERVICE
 *         │
 *         ▼
 *   ┌─────────────────────────────────────┐
 *   │ 5. Auth service calls back:         │
 *   │    - recordFailedLogin(email)       │  ← On failed login
 *   │    - clearFailedLogins(email)       │  ← On successful login
 *   └─────────────────────────────────────┘
 *
 * ============================================================================
 * GENERAL RATE LIMIT FLOW (Non-login endpoints)
 * ============================================================================
 *
 *   REQUEST COMES IN
 *         │
 *         ▼
 *   ┌─────────────────────────────────────┐
 *   │ 1. Get client IP address            │
 *   │    - Check X-Forwarded-For header   │
 *   │    - Fallback to remote address     │
 *   └─────────────────────────────────────┘
 *         │
 *         ▼
 *   ┌─────────────────────────────────────┐
 *   │ 2. Increment counter in Redis       │
 *   │    Key: "rate_limit:{ip}:general"   │
 *   │    TTL: 60 seconds                  │
 *   └─────────────────────────────────────┘
 *         │
 *         ▼
 *   ┌─────────────────────────────────────┐
 *   │ 3. Check if limit exceeded          │
 *   │    - Max 100 requests per minute    │
 *   └─────────────────────────────────────┘
 *         │ YES → 429 Too Many Requests
 *         │ NO
 *         ▼
 *   ┌─────────────────────────────────────┐
 *   │ 4. Add rate limit headers           │
 *   │    - X-RateLimit-Limit: 100         │
 *   │    - X-RateLimit-Remaining: N       │
 *   └─────────────────────────────────────┘
 *         │
 *         ▼
 *   FORWARD TO DOWNSTREAM SERVICE
 *
 * ============================================================================
 */

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
 * Supports brute-force attack prevention (Medium 2.2.2):
 * - Blocks authentication for an account after 5 failed login attempts within 60 seconds
 *
 * Rate limits:
 * - General API: 100 requests per minute per IP
 * - Login endpoint: 5 failed attempts per account in 60 seconds (brute-force protection)
 */
@Slf4j
@Component
public class RateLimitingFilter implements GlobalFilter, Ordered {

    private static final int GENERAL_RATE_LIMIT = 100;
    private static final int LOGIN_FAILED_LIMIT = 5;
    private static final Duration RATE_LIMIT_WINDOW = Duration.ofSeconds(60);
    private static final String RATE_LIMIT_KEY_PREFIX = "rate_limit:";
    private static final String LOGIN_FAILED_KEY_PREFIX = "login_failed:";

    private final ReactiveRedisTemplate<String, String> redisTemplate;

    public RateLimitingFilter(ReactiveRedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();

        // Check if this is a login endpoint
        if (isLoginEndpoint(path)) {
            return handleLoginRateLimit(exchange, chain);
        }

        // General rate limiting by IP
        return handleGeneralRateLimit(exchange, chain);
    }

    /**
     * Handle login rate limiting by account email (Requirement 2.2.2)
     * Blocks authentication for an account after 5 failed login attempts within 60 seconds
     */
    private Mono<Void> handleLoginRateLimit(ServerWebExchange exchange, GatewayFilterChain chain) {
        String email = exchange.getRequest().getQueryParams().getFirst("email");

        // If email is in request body, it will be handled by the auth service
        // Here we check if the account is already blocked
        if (email == null || email.isEmpty()) {
            // Cannot determine email from query params, proceed with request
            // The auth service should call recordFailedLogin after failed attempt
            return chain.filter(exchange);
        }

        String loginFailedKey = LOGIN_FAILED_KEY_PREFIX + email.toLowerCase();

        return redisTemplate.opsForValue()
                .get(loginFailedKey)
                .defaultIfEmpty("0")
                .flatMap(countStr -> {
                    int count = Integer.parseInt(countStr);
                    if (count >= LOGIN_FAILED_LIMIT) {
                        log.warn("Account blocked due to too many failed login attempts: {}", email);
                        exchange.getResponse().setStatusCode(HttpStatus.TOO_MANY_REQUESTS);
                        exchange.getResponse().getHeaders()
                                .add("X-RateLimit-Retry-After", String.valueOf(RATE_LIMIT_WINDOW.getSeconds()));
                        exchange.getResponse().getHeaders()
                                .add("X-Block-Reason", "Too many failed login attempts. Try again later.");
                        return exchange.getResponse().setComplete();
                    }
                    return chain.filter(exchange);
                })
                .onErrorResume(e -> {
                    log.error("Login rate limit check failed: {}", e.getMessage());
                    return chain.filter(exchange);
                });
    }

    /**
     * Record a failed login attempt for an account
     * Called by auth service after a failed login
     */
    public Mono<Long> recordFailedLogin(String email) {
        String loginFailedKey = LOGIN_FAILED_KEY_PREFIX + email.toLowerCase();

        return redisTemplate.opsForValue()
                .increment(loginFailedKey)
                .flatMap(count -> {
                    if (count == 1) {
                        return redisTemplate.expire(loginFailedKey, RATE_LIMIT_WINDOW)
                                .thenReturn(count);
                    }
                    return Mono.just(count);
                })
                .doOnNext(count -> {
                    if (count >= LOGIN_FAILED_LIMIT) {
                        log.warn("Account {} blocked after {} failed login attempts", email, count);
                    }
                });
    }

    /**
     * Clear failed login attempts after successful login
     */
    public Mono<Boolean> clearFailedLogins(String email) {
        String loginFailedKey = LOGIN_FAILED_KEY_PREFIX + email.toLowerCase();
        return redisTemplate.delete(loginFailedKey).map(count -> count > 0);
    }

    /**
     * Check if an account is currently blocked
     */
    public Mono<Boolean> isAccountBlocked(String email) {
        String loginFailedKey = LOGIN_FAILED_KEY_PREFIX + email.toLowerCase();
        return redisTemplate.opsForValue()
                .get(loginFailedKey)
                .defaultIfEmpty("0")
                .map(countStr -> Integer.parseInt(countStr) >= LOGIN_FAILED_LIMIT);
    }

    /**
     * Handle general API rate limiting by IP
     */
    private Mono<Void> handleGeneralRateLimit(ServerWebExchange exchange, GatewayFilterChain chain) {
        String clientIp = getClientIp(exchange);
        String rateLimitKey = RATE_LIMIT_KEY_PREFIX + clientIp + ":general";

        return redisTemplate.opsForValue()
                .increment(rateLimitKey)
                .flatMap(count -> {
                    if (count == 1) {
                        return redisTemplate.expire(rateLimitKey, RATE_LIMIT_WINDOW)
                                .thenReturn(count);
                    }
                    return Mono.just(count);
                })
                .flatMap(count -> {
                    if (count > GENERAL_RATE_LIMIT) {
                        log.warn("Rate limit exceeded for IP: {}", clientIp);
                        exchange.getResponse().setStatusCode(HttpStatus.TOO_MANY_REQUESTS);
                        exchange.getResponse().getHeaders()
                                .add("X-RateLimit-Retry-After", String.valueOf(RATE_LIMIT_WINDOW.getSeconds()));
                        return exchange.getResponse().setComplete();
                    }

                    exchange.getResponse().getHeaders()
                            .add("X-RateLimit-Limit", String.valueOf(GENERAL_RATE_LIMIT));
                    exchange.getResponse().getHeaders()
                            .add("X-RateLimit-Remaining", String.valueOf(Math.max(0, GENERAL_RATE_LIMIT - count)));

                    return chain.filter(exchange);
                })
                .onErrorResume(e -> {
                    log.error("Rate limiting check failed: {}", e.getMessage());
                    return chain.filter(exchange);
                });
    }

    private String getClientIp(ServerWebExchange exchange) {
        String forwardedFor = exchange.getRequest().getHeaders().getFirst("X-Forwarded-For");
        if (forwardedFor != null && !forwardedFor.isEmpty()) {
            return forwardedFor.split(",")[0].trim();
        }

        var remoteAddress = exchange.getRequest().getRemoteAddress();
        return remoteAddress != null ? remoteAddress.getAddress().getHostAddress() : "unknown";
    }

    private boolean isLoginEndpoint(String path) {
        return path.contains("/auth/login") || path.contains("/auth/admin/login");
    }

    @Override
    public int getOrder() {
        return -2;
    }
}
