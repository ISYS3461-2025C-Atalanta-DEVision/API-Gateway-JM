package com.devision.jm.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

/**
 * API Gateway Application
 *
 * Central entry point for all microservices in the DEVision Job Manager system.
 * Handles:
 * - Request routing to appropriate microservices via Service Discovery
 * - Authentication/Authorization filtering
 * - Rate limiting and circuit breaking
 * - Cross-cutting concerns (CORS, logging, etc.)
 *
 * Architecture Role: Ultimo Level (D.3.1)
 * - Acts as single entry point for all client requests
 * - Routes requests based on Eureka service registry
 * - Applies security filters before forwarding requests
 */
@SpringBootApplication
@EnableDiscoveryClient
public class ApiGatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(ApiGatewayApplication.class, args);
    }
}
