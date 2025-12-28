package com.devision.jm.gateway.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class OpenApiConfig {

    @Value("${external.api-key:devision-ja-external-api-key-2024}")
    private String externalApiKey;

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("DevVision Job Manager API Gateway")
                        .version("1.0.0")
                        .description("""
                                API Gateway for DevVision Job Manager microservices.

                                ## Authentication

                                ### For Internal Users (JWT)
                                Use Bearer token authentication with JWT obtained from `/auth-service/api/auth/login`.

                                ### For External Partners (JA Team)
                                Use API Key authentication with header: `X-API-Key: <your-api-key>`

                                ## Available Services

                                - **Auth Service** (`/auth-service/api/auth/**`) - Authentication & Authorization
                                - **Profile Service** (`/profile-service/api/**`) - Company Profiles & Events
                                - **Job Post Service** (`/jobpost-service/api/**`) - Job Listings
                                - **Payment Service** (`/payment-service/api/**`) - Stripe Subscriptions

                                ## External API Endpoints (API Key Access)

                                The following endpoints are accessible with API Key for JA team:
                                - `/profile-service/api/profiles` - Company profiles
                                - `/jobpost-service/api/job-posts` - Job post data
                                - `/payment-service/api/payments` - Payment/subscription status
                                """)
                        .contact(new Contact()
                                .name("DevVision Team")
                                .email("support@devision.com"))
                        .license(new License()
                                .name("Proprietary")
                                .url("https://devision.com")))
                .servers(List.of(
                        new Server()
                                .url("https://api-gateway-khhr.onrender.com")
                                .description("Production Server"),
                        new Server()
                                .url("http://localhost:8080")
                                .description("Local Development")))
                .components(new Components()
                        .addSecuritySchemes("bearerAuth", new SecurityScheme()
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("bearer")
                                .bearerFormat("JWT")
                                .description("JWT token from /auth-service/api/auth/login"))
                        .addSecuritySchemes("apiKeyAuth", new SecurityScheme()
                                .type(SecurityScheme.Type.APIKEY)
                                .in(SecurityScheme.In.HEADER)
                                .name("X-API-Key")
                                .description("External API Key for JA team access")))
                .addSecurityItem(new SecurityRequirement()
                        .addList("bearerAuth")
                        .addList("apiKeyAuth"));
    }
}
