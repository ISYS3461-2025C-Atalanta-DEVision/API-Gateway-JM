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
 *   │ 3. Decrypt & Validate JWE token     │
 *   │    - Decrypt with AES-256 key       │
 *   │    - Check expiration               │
 *   └─────────────────────────────────────┘
 *         │ Invalid? → 401 Unauthorized
 *         ▼
 *   ┌─────────────────────────────────────┐
 *   │ 4. Check role (if admin endpoint)   │
 *   │    - Does user have ADMIN role?     │
 *   └─────────────────────────────────────┘
 *         │ Not admin? → 403 Forbidden
 *         ▼
 *   ┌─────────────────────────────────────┐
 *   │ 5. Add user info to headers         │
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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import jakarta.annotation.PostConstruct;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

/**
 * Global Authentication Filter
 *
 * Applies JWE (encrypted token) authentication to ALL routes including auto-discovered services.
 * Updated to support requirement 2.2.1 (JWE tokens)
 *
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

    private final SecretKey encryptionKey;
    private final List<String> publicEndpoints;
    private final List<String> adminEndpoints;

    // ==================== CONSTRUCTOR ====================

    public GlobalAuthFilter(@Value("${jwt.secret:defaultSecretKeyForDevelopmentPurposesOnly123456}") String jwtSecret,
                           @Value("${gateway.public-endpoints:}") List<String> configuredPublicEndpoints,
                           @Value("${gateway.admin-endpoints:}") List<String> configuredAdminEndpoints) {

        // Generate encryption key from JWT secret (must match Auth Service)
        this.encryptionKey = generateEncryptionKey(jwtSecret);

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

    /**
     * Generate AES-256 encryption key from JWT secret
     * Must match the key generation in Auth Service's JwtConfig
     */
    private SecretKey generateEncryptionKey(String jwtSecret) {
        String keySource = jwtSecret + "_encryption";  // Must match Auth Service derivation
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] keyBytes = digest.digest(keySource.getBytes(StandardCharsets.UTF_8));
            return new SecretKeySpec(keyBytes, "AES");
        } catch (NoSuchAlgorithmException e) {
            log.error("Failed to generate encryption key: {}", e.getMessage());
            throw new RuntimeException("Failed to generate encryption key", e);
        }
    }

    @PostConstruct
    public void init() {
        log.info("GlobalAuthFilter initialized with {} public endpoints (JWE mode)", publicEndpoints.size());
        publicEndpoints.forEach(endpoint -> log.debug("  Public endpoint: {}", endpoint));

        if (!adminEndpoints.isEmpty()) {
            log.info("GlobalAuthFilter initialized with {} admin endpoints", adminEndpoints.size());
            adminEndpoints.forEach(endpoint -> log.debug("  Admin endpoint: {}", endpoint));
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
            // ========== CHECK 3: Decrypt and validate JWE token (2.2.1) ==========
            JWTClaimsSet claims = decryptAndValidateToken(token);

            if (claims == null) {
                return onError(exchange, "Invalid token", HttpStatus.UNAUTHORIZED);
            }

            // Check if token is expired
            Date expiration = claims.getExpirationTime();
            if (expiration != null && expiration.before(new Date())) {
                log.warn("Token expired for request to {}", path);
                return onError(exchange, "Token has expired", HttpStatus.UNAUTHORIZED);
            }

            // ========== CHECK 4: Is this an admin endpoint? ==========
            if (isAdminEndpoint(path)) {
                String role = claims.getStringClaim(ROLE_CLAIM);
                if (!ADMIN_ROLE.equals(role)) {
                    log.warn("Non-admin user attempted to access admin endpoint: {}", path);
                    return onError(exchange, "Admin access required", HttpStatus.FORBIDDEN);
                }
            }

            // ========== ALL CHECKS PASSED - Forward to downstream service ==========
            String userId = claims.getStringClaim(USER_ID_CLAIM);
            String email = claims.getStringClaim(EMAIL_CLAIM);
            String role = claims.getStringClaim(ROLE_CLAIM);

            ServerHttpRequest modifiedRequest = request.mutate()
                    .header("X-User-Id", userId != null ? userId : "")
                    .header("X-User-Email", email != null ? email : "")
                    .header("X-User-Role", role != null ? role : "")
                    .build();

            return chain.filter(exchange.mutate().request(modifiedRequest).build());

        } catch (ParseException e) {
            log.warn("Invalid JWE token format: {}", e.getMessage());
            return onError(exchange, "Invalid token format", HttpStatus.UNAUTHORIZED);
        } catch (JOSEException e) {
            log.warn("Failed to decrypt JWE token: {}", e.getMessage());
            return onError(exchange, "Invalid token", HttpStatus.UNAUTHORIZED);
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

    /**
     * Decrypt and validate JWE token (Requirement 2.2.1)
     * Uses AES-256-GCM direct encryption
     */
    private JWTClaimsSet decryptAndValidateToken(String token) throws ParseException, JOSEException {
        // Parse the JWE token
        EncryptedJWT encryptedJWT = EncryptedJWT.parse(token);

        // Decrypt with AES-256 key
        DirectDecrypter decrypter = new DirectDecrypter(encryptionKey);
        encryptedJWT.decrypt(decrypter);

        // Return decrypted claims
        return encryptedJWT.getJWTClaimsSet();
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
