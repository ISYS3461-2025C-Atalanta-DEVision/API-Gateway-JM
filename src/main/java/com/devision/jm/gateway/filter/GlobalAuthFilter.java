package com.devision.jm.gateway.filter;

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

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Global Authentication Filter
 *
 * Applies JWT authentication to ALL routes including auto-discovered services.
 * Public endpoints are configurable via application.yml
 */
@Slf4j
@Component
public class GlobalAuthFilter implements GlobalFilter, Ordered {

    private static final String BEARER_PREFIX = "Bearer ";
    private static final String ROLE_CLAIM = "role";
    private static final String USER_ID_CLAIM = "userId";
    private static final String EMAIL_CLAIM = "email";
    private static final String TOKEN_REVOKED_KEY_PREFIX = "revoked:";

    private final ReactiveRedisTemplate<String, String> redisTemplate;
    private final SecretKey signingKey;

    @Value("${gateway.public-endpoints:/actuator/health,/api/v1/auth/login,/api/v1/auth/register,/api/v1/auth/refresh}")
    private List<String> publicEndpoints;

    public GlobalAuthFilter(ReactiveRedisTemplate<String, String> redisTemplate,
                           @Value("${jwt.secret:defaultSecretKeyForDevelopmentPurposesOnly123456}") String jwtSecret) {
        this.redisTemplate = redisTemplate;
        this.signingKey = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();

        // Skip authentication for public endpoints
        if (isPublicEndpoint(path)) {
            log.debug("Public endpoint accessed: {}", path);
            return chain.filter(exchange);
        }

        // Extract Authorization header
        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            return onError(exchange, "Missing or invalid Authorization header", HttpStatus.UNAUTHORIZED);
        }

        String token = authHeader.substring(BEARER_PREFIX.length());

        try {
            // Validate and parse JWT
            Claims claims = validateToken(token);

            // Check if token is revoked (Redis check)
            return checkTokenRevocation(token)
                    .flatMap(isRevoked -> {
                        if (isRevoked) {
                            return onError(exchange, "Token has been revoked", HttpStatus.UNAUTHORIZED);
                        }

                        // Add user info to headers for downstream services
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
        // Run before routing filter
        return -100;
    }

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
                .onErrorReturn(false); // If Redis is unavailable, allow the request
    }

    private boolean isPublicEndpoint(String path) {
        return publicEndpoints.stream()
                .anyMatch(endpoint -> {
                    // Support wildcard patterns like /api/v1/auth/**
                    if (endpoint.endsWith("/**")) {
                        String prefix = endpoint.substring(0, endpoint.length() - 3);
                        return path.startsWith(prefix);
                    }
                    return path.equals(endpoint) || path.startsWith(endpoint);
                });
    }

    private Mono<Void> onError(ServerWebExchange exchange, String message, HttpStatus status) {
        log.warn("Authentication failed: {} - {}", status, message);
        exchange.getResponse().setStatusCode(status);
        exchange.getResponse().getHeaders().add("X-Auth-Error", message);
        return exchange.getResponse().setComplete();
    }
}
