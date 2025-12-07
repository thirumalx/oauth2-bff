/**
 * 
 */
package com.thirumal.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

/**
 * @author Thirumal
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(
                    "/bff/login",                  // public login
                    "/authorized",             // OIDC callback
                    "/error",                  // error pages
                    "/health"                  // health endpoint
                ).permitAll()
                .anyRequest().authenticated() // everything else protected
            )

            // Disable Spring Security's default login page
            .formLogin(AbstractHttpConfigurer::disable)
            .oauth2Login(AbstractHttpConfigurer::disable)

            // BFF uses session + cookies
            .csrf(AbstractHttpConfigurer::disable) // optional based on your case
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login")
            );

        return http.build();
    }

}

