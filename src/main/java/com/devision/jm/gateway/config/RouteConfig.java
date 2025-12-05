package com.devision.jm.gateway.config;

import com.devision.jm.gateway.filter.AuthenticationFilter;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Route Configuration for API Gateway
 *
 * Defines routing rules for all microservices.
 * Uses Eureka service discovery (lb://) for dynamic service resolution.
 */
@Configuration
public class RouteConfig {

    private final AuthenticationFilter authenticationFilter;

    public RouteConfig(AuthenticationFilter authenticationFilter) {
        this.authenticationFilter = authenticationFilter;
    }

    @Bean
    public RouteLocator customRouteLocator(RouteLocatorBuilder builder) {
        return builder.routes()
                // Auth Service Routes - Public endpoints (no authentication required)
                .route("auth-service-public", r -> r
                        .path("/api/v1/auth/**")
                        .filters(f -> f
                                .stripPrefix(0)
                                .circuitBreaker(c -> c
                                        .setName("authServiceCircuitBreaker")
                                        .setFallbackUri("forward:/fallback/auth")))
                        .uri("lb://AUTH-SERVICE"))

                // Company Registration - Public endpoint
                .route("company-registration", r -> r
                        .path("/api/v1/companies/register")
                        .filters(f -> f
                                .stripPrefix(0))
                        .uri("lb://AUTH-SERVICE"))

                // Company Profile Routes - Requires authentication
                .route("company-service-secured", r -> r
                        .path("/api/v1/companies/**")
                        .filters(f -> f
                                .filter(authenticationFilter.apply(new AuthenticationFilter.Config()))
                                .stripPrefix(0))
                        .uri("lb://COMPANY-SERVICE"))

                // Job Post Routes - Mixed (some public, some secured)
                .route("job-post-service", r -> r
                        .path("/api/v1/jobs/**")
                        .filters(f -> f
                                .filter(authenticationFilter.apply(new AuthenticationFilter.Config()))
                                .stripPrefix(0))
                        .uri("lb://JOB-SERVICE"))

                // Admin Routes - Requires admin authentication
                .route("admin-service", r -> r
                        .path("/api/v1/admin/**")
                        .filters(f -> f
                                .filter(authenticationFilter.apply(
                                        new AuthenticationFilter.Config().setRequireAdmin(true)))
                                .stripPrefix(0))
                        .uri("lb://AUTH-SERVICE"))

                // Notification Service Routes
                .route("notification-service", r -> r
                        .path("/api/v1/notifications/**")
                        .filters(f -> f
                                .filter(authenticationFilter.apply(new AuthenticationFilter.Config()))
                                .stripPrefix(0))
                        .uri("lb://NOTIFICATION-SERVICE"))

                .build();
    }
}
