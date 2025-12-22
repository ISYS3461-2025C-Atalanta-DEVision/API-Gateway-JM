package com.devision.jm.gateway.filter;

import com.devision.jm.gateway.config.ExternalApiConfig;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * External API Key Filter for Service-to-Service Communication
 *
 * This filter validates external API keys for partner systems (e.g., Job Applicant team)
 * to access specific endpoints. Supports dual authentication:
 * - External API Key: For partner systems (JA team)
 * - JWT Token: For internal users (JM team)
 *
 * Flow:
 * 1. Check if X-External-Api-Key header is present
 * 2. If present and valid, mark as validated (bypass JWT auth)
 * 3. If present but invalid, return 401 Unauthorized
 * 4. If not present, let request continue to JWT validation
 *
 * Configuration in application.yml:
 *   external:
 *     api-key: your-secret-key-for-ja-team
 *     endpoints:
 *       - /profile-service/api/profiles
 */
@Slf4j
@Component
public class ExternalApiKeyFilter implements GlobalFilter, Ordered {

    public static final String EXTERNAL_API_KEY_HEADER = "X-External-Api-Key";
    private static final String EXTERNAL_API_VALIDATED_HEADER = "X-External-Api-Validated";

    private final ExternalApiConfig config;

    public ExternalApiKeyFilter(ExternalApiConfig config) {
        this.config = config;

        // Log initialization
        String apiKey = config.getApiKey();
        List<String> endpoints = config.getEndpoints();

        if (apiKey == null || apiKey.isEmpty()) {
            log.info("ExternalApiKeyFilter disabled - no external API key configured");
        } else {
            log.info("ExternalApiKeyFilter initialized with {} external endpoints", endpoints.size());
            endpoints.forEach(ep -> log.info("  - External endpoint: {}", ep));
        }
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String apiKey = config.getApiKey();
        List<String> endpoints = config.getEndpoints();

        // Skip if external API key is not configured
        if (apiKey == null || apiKey.isEmpty()) {
            return chain.filter(exchange);
        }

        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();

        // Check if this is an external API endpoint
        if (!isExternalEndpoint(path, endpoints)) {
            return chain.filter(exchange);
        }

        // Check if external API key header is present
        String providedApiKey = request.getHeaders().getFirst(EXTERNAL_API_KEY_HEADER);

        // If no API key provided, let request continue to JWT validation
        if (providedApiKey == null || providedApiKey.isBlank()) {
            log.debug("No external API key provided for: {}, falling through to JWT auth", path);
            return chain.filter(exchange);
        }

        // API key is provided - validate it
        if (!apiKey.equals(providedApiKey)) {
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

    private boolean isExternalEndpoint(String path, List<String> endpoints) {
        if (endpoints == null || endpoints.isEmpty()) {
            return false;
        }

        return endpoints.stream()
                .anyMatch(pattern -> {
                    if (pattern.endsWith("/**")) {
                        String prefix = pattern.substring(0, pattern.length() - 3);
                        return path.startsWith(prefix);
                    }
                    // Match:
                    // 1. Exact path: /profile-service/api/profiles
                    // 2. Path with query: /profile-service/api/profiles?search=...
                    // 3. Path with ID: /profile-service/api/profiles/123abc
                    return path.equals(pattern) ||
                           path.startsWith(pattern + "?") ||
                           path.startsWith(pattern + "/");
                });
    }

    private Mono<Void> onError(ServerWebExchange exchange, String message, HttpStatus status) {
        log.warn("External API authentication failed: {} - {}", status, message);
        exchange.getResponse().setStatusCode(status);
        exchange.getResponse().getHeaders().add("X-Auth-Error", message);
        return exchange.getResponse().setComplete();
    }
}
