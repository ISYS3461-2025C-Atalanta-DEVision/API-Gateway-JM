package com.devision.jm.gateway.filter;

/*
 * ============================================================================
 * GLOBAL AUTH FILTER - CODE FLOW
 * ============================================================================
 *
 * This filter runs on ALL requests (including auto-discovered services).
 *
 *   REQUEST COMES IN
 *         │
 *         ▼
 *   ┌─────────────────────────────────────┐
 *   │ 1. Is this a public endpoint?       │
 *   │    - Check against application.yml  │
 *   │    - Supports wildcards like /**    │
 *   └─────────────────────────────────────┘
 *         │ Public? → Skip auth, forward request
 *         ▼
 *   ┌─────────────────────────────────────┐
 *   │ 2. Check Authorization header       │
 *   │    - Must exist                     │
 *   │    - Must start with "Bearer "      │
 *   └─────────────────────────────────────┘
 *         │ Missing? → 401 Unauthorized
 *         ▼
 *   ┌─────────────────────────────────────┐
 *   │ 3. Validate JWT token               │
 *   │    - Check signature (not tampered) │
 *   │    - Check expiration               │
 *   └─────────────────────────────────────┘
 *         │ Invalid? → 401 Unauthorized
 *         ▼
 *   ┌─────────────────────────────────────┐
 *   │ 4. Check Redis for revocation       │
 *   │    - Was user logged out?           │
 *   └─────────────────────────────────────┘
 *         │ Revoked? → 401 Unauthorized
 *         ▼
 *   ┌─────────────────────────────────────┐
 *   │ 5. Check role (if admin endpoint)   │
 *   │    - Does user have ADMIN role?     │
 *   └─────────────────────────────────────┘
 *         │ Not admin? → 403 Forbidden
 *         ▼
 *   ┌─────────────────────────────────────┐
 *   │ 6. Add user info to headers         │
 *   │    - X-User-Id                      │
 *   │    - X-User-Email                   │
 *   │    - X-User-Role                    │
 *   └─────────────────────────────────────┘
 *         │
 *         ▼
 *   FORWARD TO DOWNSTREAM SERVICE
 *
 * ============================================================================
 */

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import jakarta.annotation.PostConstruct;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

/**
 * Global Authentication Filter
 *
 * Applies JWT authentication to ALL routes including auto-discovered services.
 * - Public endpoints: configurable via application.yml (gateway.public-endpoints)
 * - Admin endpoints: configurable via application.yml (gateway.admin-endpoints)
 */
@Slf4j
@Component
public class GlobalAuthFilter implements GlobalFilter, Ordered {

    // ==================== CONSTANTS ====================

    private static final String BEARER_PREFIX = "Bearer ";
    private static final String ROLE_CLAIM = "role";
    private static final String USER_ID_CLAIM = "userId";
    private static final String EMAIL_CLAIM = "email";
    private static final String TOKEN_REVOKED_KEY_PREFIX = "revoked:";
    private static final String ADMIN_ROLE = "ADMIN";

    // Default public endpoints (fallback if application.yml is not configured)
    private static final List<String> DEFAULT_PUBLIC_ENDPOINTS = Arrays.asList(
            "/actuator/health",
            "/actuator/info",
            "/auth-service/api/auth/login",
            "/auth-service/api/auth/register",
            "/auth-service/api/auth/refresh",
            "/auth-service/api/auth/activate",
            "/auth-service/api/auth/forgot-password",
            "/auth-service/api/auth/reset-password",
            "/auth-service/api/auth/countries",
            "/auth-service/api/auth/validate",
            "/auth-service/oauth2",
            "/auth-service/login/oauth2",
            "/api/auth/login",
            "/api/auth/register",
            "/api/auth/refresh",
            "/api/auth/activate",
            "/api/auth/forgot-password",
            "/api/auth/reset-password",
            "/api/auth/countries"
    );

    // ==================== INSTANCE VARIABLES ====================

    private final ReactiveRedisTemplate<String, String> redisTemplate;
    private final SecretKey signingKey;
    private final List<String> publicEndpoints;
    private final List<String> adminEndpoints;

    // ==================== CONSTRUCTOR ====================

    public GlobalAuthFilter(ReactiveRedisTemplate<String, String> redisTemplate,
                           @Value("${jwt.secret:defaultSecretKeyForDevelopmentPurposesOnly123456}") String jwtSecret,
                           @Value("${gateway.public-endpoints:}") List<String> configuredPublicEndpoints,
                           @Value("${gateway.admin-endpoints:}") List<String> configuredAdminEndpoints) {
        this.redisTemplate = redisTemplate;
        this.signingKey = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));

        // Use configured public endpoints from YAML if available, otherwise use defaults
        this.publicEndpoints = (configuredPublicEndpoints != null && !configuredPublicEndpoints.isEmpty()
                && !configuredPublicEndpoints.get(0).isEmpty())
                ? configuredPublicEndpoints
                : DEFAULT_PUBLIC_ENDPOINTS;

        // Use configured admin endpoints from YAML (empty list if not configured)
        this.adminEndpoints = (configuredAdminEndpoints != null && !configuredAdminEndpoints.isEmpty()
                && !configuredAdminEndpoints.get(0).isEmpty())
                ? configuredAdminEndpoints
                : List.of();
    }

    @PostConstruct
    public void init() {
        log.info("GlobalAuthFilter initialized with {} public endpoints", publicEndpoints.size());
        publicEndpoints.forEach(endpoint -> log.info("  Public endpoint: {}", endpoint));

        if (!adminEndpoints.isEmpty()) {
            log.info("GlobalAuthFilter initialized with {} admin endpoints", adminEndpoints.size());
            adminEndpoints.forEach(endpoint -> log.info("  Admin endpoint: {}", endpoint));
        }
    }

    // ==================== MAIN FILTER LOGIC ====================

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();

        // ========== CHECK 1: Is this a public endpoint? ==========
        if (isPublicEndpoint(path)) {
            log.debug("Public endpoint accessed: {}", path);
            return chain.filter(exchange);
        }

        // ========== CHECK 2: Does the request have an Authorization header? ==========
        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            return onError(exchange, "Missing or invalid Authorization header", HttpStatus.UNAUTHORIZED);
        }

        String token = authHeader.substring(BEARER_PREFIX.length());

        try {
            // ========== CHECK 3: Is the JWT token valid? ==========
            Claims claims = validateToken(token);

            // ========== CHECK 4: Has the token been revoked? ==========
            return checkTokenRevocation(token)
                    .flatMap(isRevoked -> {
                        if (isRevoked) {
                            return onError(exchange, "Token has been revoked", HttpStatus.UNAUTHORIZED);
                        }

                        // ========== CHECK 5: Is this an admin endpoint? ==========
                        if (isAdminEndpoint(path)) {
                            String role = claims.get(ROLE_CLAIM, String.class);
                            if (!ADMIN_ROLE.equals(role)) {
                                log.warn("Non-admin user attempted to access admin endpoint: {}", path);
                                return onError(exchange, "Admin access required", HttpStatus.FORBIDDEN);
                            }
                        }

                        // ========== ALL CHECKS PASSED - Forward to downstream service ==========
                        ServerHttpRequest modifiedRequest = request.mutate()
                                .header("X-User-Id", claims.get(USER_ID_CLAIM, String.class))
                                .header("X-User-Email", claims.get(EMAIL_CLAIM, String.class))
                                .header("X-User-Role", claims.get(ROLE_CLAIM, String.class))
                                .build();

                        return chain.filter(exchange.mutate().request(modifiedRequest).build());
                    });

        } catch (ExpiredJwtException e) {
            log.warn("Token expired for request to {}", path);
            return onError(exchange, "Token has expired", HttpStatus.UNAUTHORIZED);
        } catch (Exception e) {
            log.error("Token validation failed: {}", e.getMessage());
            return onError(exchange, "Invalid token", HttpStatus.UNAUTHORIZED);
        }
    }

    @Override
    public int getOrder() {
        return -100;
    }

    // ==================== HELPER METHODS ====================

    private Claims validateToken(String token) {
        return Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private Mono<Boolean> checkTokenRevocation(String token) {
        String tokenKey = TOKEN_REVOKED_KEY_PREFIX + token;
        return redisTemplate.hasKey(tokenKey)
                .onErrorReturn(false);
    }

    private boolean isPublicEndpoint(String path) {
        return matchesAnyPattern(path, publicEndpoints);
    }

    private boolean isAdminEndpoint(String path) {
        return matchesAnyPattern(path, adminEndpoints);
    }

    /**
     * Checks if a path matches any pattern in the list
     * Supports wildcard patterns like /api/admin/**
     */
    private boolean matchesAnyPattern(String path, List<String> patterns) {
        return patterns.stream()
                .anyMatch(pattern -> {
                    if (pattern.endsWith("/**")) {
                        String prefix = pattern.substring(0, pattern.length() - 3);
                        return path.startsWith(prefix);
                    }
                    return path.equals(pattern) || path.startsWith(pattern);
                });
    }

    private Mono<Void> onError(ServerWebExchange exchange, String message, HttpStatus status) {
        log.warn("Authentication failed: {} - {}", status, message);
        exchange.getResponse().setStatusCode(status);
        exchange.getResponse().getHeaders().add("X-Auth-Error", message);
        return exchange.getResponse().setComplete();
    }
}
