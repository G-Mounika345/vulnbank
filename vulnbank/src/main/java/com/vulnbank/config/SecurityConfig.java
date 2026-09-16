package com.vulnbank.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Collections;

/**
 * A05:2021 Security Misconfiguration.
 *
 * On purpose:
 *  - CSRF protection globally disabled (try forging a cross-site POST to
 *    /transfer from an external HTML page while logged in).
 *  - CORS allows any origin with credentials.
 *  - Every URL is permitAll() at the framework level; "access control" for
 *    /admin/** is instead done ad-hoc inside AdminController by checking a
 *    request parameter, which you can simply omit or forge (A01: Broken
 *    Access Control) - a very common real-world anti-pattern.
 *  - The H2 console and actuator endpoints are open with no auth.
 */
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf().disable()
            .cors().configurationSource(corsConfigurationSource())
            .and()
            .headers().frameOptions().disable() // needed for h2-console, also weakens clickjacking defenses
            .and()
            .authorizeHttpRequests(auth -> auth.anyRequest().permitAll());
        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOriginPatterns(Collections.singletonList("*"));
        config.setAllowedMethods(Collections.singletonList("*"));
        config.setAllowedHeaders(Collections.singletonList("*"));
        config.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
