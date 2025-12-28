package com.devision.jm.gateway.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.config.ResourceHandlerRegistry;
import org.springframework.web.reactive.config.WebFluxConfigurer;

@Configuration
public class WebFluxConfig implements WebFluxConfigurer {

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        // Serve static OpenAPI spec file
        registry.addResourceHandler("/openapi.yaml")
                .addResourceLocations("classpath:/static/");
    }
}
