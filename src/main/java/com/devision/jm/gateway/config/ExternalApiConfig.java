package com.devision.jm.gateway.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.List;

/**
 * Configuration properties for external API key authentication.
 *
 * Used by ExternalApiKeyFilter to validate requests from partner systems
 * (e.g., Job Applicant team) that need to access specific endpoints
 * without JWT authentication.
 */
@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "external")
public class ExternalApiConfig {

    /**
     * The external API key for partner systems.
     * Must match the X-External-Api-Key header in requests.
     */
    private String apiKey = "";

    /**
     * List of endpoint paths that can be accessed with the external API key.
     * Supports wildcard patterns ending with /**
     */
    private List<String> endpoints = new ArrayList<>();
}
