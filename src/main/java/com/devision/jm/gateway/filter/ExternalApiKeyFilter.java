package com.devision.jm.gateway.filter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import jakarta.annotation.PostConstruct;
import java.util.List;

/**
 * External API Key Filter for Service-to-Service Communication
 *
 * This filter validates external API keys for partner systems (e.g., Job Applicant team)
 * to access specific endpoints without JWT authentication.
 *
 * Flow:
 * 1. Check if the request path matches an external API endpoint
 * 2. If yes, validate the X-External-Api-Key header
 * 3. If valid, allow the request to proceed (bypass JWT auth)
 * 4. If invalid or missing, return 401 Unauthorized
 *
 * Configuration in application.yml:
 *   external:
 *     api-key: your-secret-key-for-ja-team
 *     endpoints:
 *       - /profile-service/api/profiles
 *       - /api/profiles
 * 
 * Request: GET /profile-service/api/profiles
         X-External-Api-Key: devision-ja-external-api-key-2025
                    │
                    ▼
         Is path whitelisted? → YES
                    │
                    ▼
         Is API key correct? → YES
                    │
                    ▼
         Add X-External-Api-Validated: true
 * 
 * 
 */
@Slf4j
@Component
public class ExternalApiKeyFilter implements GlobalFilter, Ordered {

    public static final String EXTERNAL_API_KEY_HEADER = "X-External-Api-Key";
    private static final String EXTERNAL_API_VALIDATED_HEADER = "X-External-Api-Validated";

    @Value("${external.api-key:}")
    private String externalApiKey;

    @Value("${external.endpoints:}")
    private List<String> externalEndpoints;

    @PostConstruct
    public void init() {
        if (externalApiKey == null || externalApiKey.isEmpty()) {
            log.info("ExternalApiKeyFilter disabled - no external API key configured");
        } else {
            log.info("ExternalApiKeyFilter initialized with {} external endpoints",
                    externalEndpoints != null ? externalEndpoints.size() : 0);
            if (externalEndpoints != null && !externalEndpoints.isEmpty()) {
                externalEndpoints.forEach(ep -> log.info("  - External endpoint: {}", ep));
            }
        }
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // Skip if external API key is not configured
        if (externalApiKey == null || externalApiKey.isEmpty()) {
            return chain.filter(exchange);
        }

        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();

        // Check if this is an external API endpoint
        if (!isExternalEndpoint(path)) {
            return chain.filter(exchange);
        }

        // Validate external API key
        String providedApiKey = request.getHeaders().getFirst(EXTERNAL_API_KEY_HEADER);

        if (providedApiKey == null || providedApiKey.isBlank()) {
            log.warn("Missing external API key for request to: {}", path);
            return onError(exchange, "Missing external API key", HttpStatus.UNAUTHORIZED);
        }

        if (!externalApiKey.equals(providedApiKey)) {
            log.warn("Invalid external API key for request to: {}", path);
            return onError(exchange, "Invalid external API key", HttpStatus.UNAUTHORIZED);
        }

        log.info("Valid external API key for request to: {}", path);

        // Add header to indicate external API validation passed
        // This tells GlobalAuthFilter to skip JWE validation
        ServerHttpRequest modifiedRequest = request.mutate()
                .header(EXTERNAL_API_VALIDATED_HEADER, "true")
                .build();

        return chain.filter(exchange.mutate().request(modifiedRequest).build());
    }

    @Override
    public int getOrder() {
        // Run BEFORE GlobalAuthFilter (-100) so we can set the validation header
        return -150;
    }

    private boolean isExternalEndpoint(String path) {
        if (externalEndpoints == null || externalEndpoints.isEmpty()) {
            return false;
        }

        return externalEndpoints.stream()
                .anyMatch(pattern -> {
                    if (pattern.endsWith("/**")) {
                        String prefix = pattern.substring(0, pattern.length() - 3);
                        return path.startsWith(prefix);
                    }
                    // Match exact path or path with query params
                    return path.equals(pattern) || path.startsWith(pattern + "?") || path.startsWith(pattern);
                });
    }

    private Mono<Void> onError(ServerWebExchange exchange, String message, HttpStatus status) {
        log.warn("External API authentication failed: {} - {}", status, message);
        exchange.getResponse().setStatusCode(status);
        exchange.getResponse().getHeaders().add("X-Auth-Error", message);
        return exchange.getResponse().setComplete();
    }
}
