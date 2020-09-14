package com.example.springcloudgateway.config;

import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoders;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http,
                                                         ReactiveClientRegistrationRepository clientRegistrationRepository) {
        http.oauth2Login().and().oauth2ResourceServer().jwt();

        http.authorizeExchange()
                .pathMatchers("/actuator/health").permitAll()
                .anyExchange().authenticated();

        return http.build();
    }

    @Bean
    public ReactiveJwtDecoder reactiveJwtDecoder(OAuth2ResourceServerProperties properties) {
        return ReactiveJwtDecoders.fromOidcIssuerLocation(properties.getJwt().getIssuerUri());
    }

}
