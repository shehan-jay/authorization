package com.auth.bearertoken;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@SpringBootApplication
public class BearerTokenApplication {
    public static void main(String[] args) {
        SpringApplication.run(BearerTokenApplication.class, args);
    }

    @Configuration
    @EnableWebSecurity
    public static class SecurityConfig extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                .antMatchers("/api/token").permitAll()
                .antMatchers("/api/secure/**").authenticated()
                .anyRequest().permitAll()
                .and()
                .addFilterBefore(new BearerTokenFilter(), UsernamePasswordAuthenticationFilter.class);
        }
    }

    @RestController
    public static class TokenController {
        private static final Map<String, TokenInfo> TOKENS = new ConcurrentHashMap<>();

        @PostMapping("/api/token")
        public Map<String, String> getToken() {
            String token = UUID.randomUUID().toString();
            TOKENS.put(token, new TokenInfo(System.currentTimeMillis(), "user123"));

            Map<String, String> response = new HashMap<>();
            response.put("access_token", token);
            response.put("token_type", "Bearer");
            response.put("expires_in", "86400");
            return response;
        }

        public static class TokenInfo {
            private final long createdAt;
            private final String userId;

            public TokenInfo(long createdAt, String userId) {
                this.createdAt = createdAt;
                this.userId = userId;
            }

            public boolean isValid() {
                return System.currentTimeMillis() - createdAt < 86400000; // 24 hours
            }

            public String getUserId() {
                return userId;
            }
        }

        public static Map<String, TokenInfo> getTokens() {
            return TOKENS;
        }
    }
} 