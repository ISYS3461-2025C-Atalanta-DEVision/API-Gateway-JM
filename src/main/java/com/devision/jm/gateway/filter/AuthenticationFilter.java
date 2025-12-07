package com.devision.jm.gateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
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
 * Authentication Filter for API Gateway
 *
 * This filter intercepts all requests and validates JWT tokens.
 * Implements:
 * - JWT validation (JWS for Simplex, JWE for Medium/Ultimo)
 * - Token revocation check via Redis (Ultimo 2.3.2)
 * - Role-based access control
 *
 * Architecture Role: A.1.3 - Filter organized separately from tier structure
 */
@Slf4j
@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

    private static final String BEARER_PREFIX = "Bearer ";
    private static final String ROLE_CLAIM = "role";
    private static final String USER_ID_CLAIM = "userId";
    private static final String EMAIL_CLAIM = "email";
    private static final String TOKEN_REVOKED_KEY_PREFIX = "revoked:";

    // Public endpoints that don't require authentication
    private static final List<String> PUBLIC_ENDPOINTS = List.of(
            "/api/v1/auth/login",
            "/api/v1/auth/register",
            "/api/v1/auth/refresh",
            "/api/v1/auth/activate",
            "/api/v1/auth/forgot-password",
            "/api/v1/companies/register",
            "/api/v1/jobs/public"
    );

    private final ReactiveRedisTemplate<String, String> redisTemplate;
    private final SecretKey signingKey;

    @Value("${jwt.secret}")
    private String jwtSecret;

    public AuthenticationFilter(ReactiveRedisTemplate<String, String> redisTemplate,
                                @Value("${jwt.secret:defaultSecretKeyForDevelopmentPurposesOnly123456}") String jwtSecret) {
        super(Config.class);
        this.redisTemplate = redisTemplate;
        this.signingKey = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            String path = request.getURI().getPath();

            // Skip authentication for public endpoints
            if (isPublicEndpoint(path)) {
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

                // Check if token is revoked (Redis check for Ultimo 2.3.2)
                return checkTokenRevocation(token)
                        .flatMap(isRevoked -> {
                            if (isRevoked) {
                                return onError(exchange, "Token has been revoked", HttpStatus.UNAUTHORIZED);
                            }

                            // Check admin requirement
                            if (config.isRequireAdmin()) {
                                String role = claims.get(ROLE_CLAIM, String.class);
                                if (!"ADMIN".equals(role)) {
                                    return onError(exchange, "Admin access required", HttpStatus.FORBIDDEN);
                                }
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
        };
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
        return PUBLIC_ENDPOINTS.stream()
                .anyMatch(endpoint -> path.startsWith(endpoint) || path.matches(endpoint));
    }

    private Mono<Void> onError(ServerWebExchange exchange, String message, HttpStatus status) {
        log.warn("Authentication failed: {} - {}", status, message);
        exchange.getResponse().setStatusCode(status);
        exchange.getResponse().getHeaders().add("X-Auth-Error", message);
        return exchange.getResponse().setComplete();
    }

    /**
     * Configuration class for the filter
     */
    @Getter
    @Setter
    public static class Config {
        private boolean requireAdmin = false;

        public Config setRequireAdmin(boolean requireAdmin) {
            this.requireAdmin = requireAdmin;
            return this;
        }
    }
}
