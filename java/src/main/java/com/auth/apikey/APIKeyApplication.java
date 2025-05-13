package com.auth.apikey;

import com.auth.base.BaseAuth;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.ResponseEntity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@SpringBootApplication
public class APIKeyApplication {
    public static void main(String[] args) {
        SpringApplication.run(APIKeyApplication.class, args);
    }

    @Configuration
    @EnableWebSecurity
    public static class SecurityConfig extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/api/keys").permitAll()
                .antMatchers("/api/secure/**").authenticated()
                .anyRequest().permitAll()
                .and()
                .addFilterBefore(apiKeyAuthFilter(), UsernamePasswordAuthenticationFilter.class);
        }

        @Bean
        public APIKeyAuthFilter apiKeyAuthFilter() {
            return new APIKeyAuthFilter();
        }
    }

    public static class APIKeyAuth extends BaseAuth {
        private final Map<String, APIKeyInfo> apiKeys = new ConcurrentHashMap<>();

        public APIKeyAuth() {
            // Add a test API key
            String testKey = "sk_test_51H7qXKJw3Jw3Jw3Jw3Jw3Jw3";
            apiKeys.put(testKey, new APIKeyInfo(
                "user_123",
                Instant.now().getEpochSecond(),
                Instant.now().plusSeconds(30 * 24 * 60 * 60).getEpochSecond(),
                Arrays.asList("read", "write")
            ));
        }

        public String generateApiKey(String userId, List<String> permissions, int expiresInDays) {
            String apiKey = "sk_test_" + UUID.randomUUID().toString().replace("-", "");
            apiKeys.put(apiKey, new APIKeyInfo(
                userId,
                Instant.now().getEpochSecond(),
                Instant.now().plusSeconds(expiresInDays * 24 * 60 * 60).getEpochSecond(),
                permissions
            ));
            return apiKey;
        }

        public boolean authenticate(HttpServletRequest request) {
            String apiKey = request.getHeader("X-API-Key");
            if (apiKey == null || !apiKeys.containsKey(apiKey)) {
                return false;
            }

            APIKeyInfo keyInfo = apiKeys.get(apiKey);
            if (Instant.now().getEpochSecond() > keyInfo.expiresAt) {
                return false;
            }

            request.setAttribute("userId", keyInfo.userId);
            request.setAttribute("permissions", keyInfo.permissions);
            return true;
        }
    }

    public static class APIKeyInfo {
        public final String userId;
        public final long createdAt;
        public final long expiresAt;
        public final List<String> permissions;

        public APIKeyInfo(String userId, long createdAt, long expiresAt, List<String> permissions) {
            this.userId = userId;
            this.createdAt = createdAt;
            this.expiresAt = expiresAt;
            this.permissions = permissions;
        }
    }

    public static class APIKeyAuthFilter extends OncePerRequestFilter {
        private final APIKeyAuth auth = new APIKeyAuth();

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws ServletException, IOException {
            if (!auth.authenticate(request)) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("Invalid or expired API key");
                return;
            }
            chain.doFilter(request, response);
        }
    }

    @RestController
    @RequestMapping("/api")
    public static class SecureController {
        private final APIKeyAuth auth = new APIKeyAuth();

        @PostMapping("/keys")
        public ResponseEntity<Map<String, Object>> createApiKey(@RequestBody Map<String, Object> request) {
            String userId = (String) request.get("user_id");
            @SuppressWarnings("unchecked")
            List<String> permissions = (List<String>) request.getOrDefault("permissions", Collections.singletonList("read"));
            int expiresInDays = (int) request.getOrDefault("expires_in_days", 30);

            if (userId == null) {
                return ResponseEntity.badRequest().body(Collections.singletonMap("error", "user_id is required"));
            }

            String apiKey = auth.generateApiKey(userId, permissions, expiresInDays);
            Map<String, Object> response = new HashMap<>();
            response.put("api_key", apiKey);
            response.put("user_id", userId);
            response.put("permissions", permissions);
            response.put("expires_in_days", expiresInDays);

            return ResponseEntity.ok(response);
        }

        @GetMapping("/secure")
        public ResponseEntity<Map<String, Object>> secureGet(HttpServletRequest request) {
            Map<String, Object> response = new HashMap<>();
            response.put("message", "This is a secure endpoint that requires API Key authentication");
            response.put("status", "success");
            response.put("user_id", request.getAttribute("userId"));
            response.put("permissions", request.getAttribute("permissions"));

            return ResponseEntity.ok(response);
        }

        @PostMapping("/secure")
        public ResponseEntity<Map<String, Object>> securePost(
                HttpServletRequest request,
                @RequestBody(required = false) Map<String, Object> body) {
            Map<String, Object> response = new HashMap<>();
            response.put("message", "This is a secure endpoint that requires API Key authentication");
            response.put("status", "success");
            response.put("user_id", request.getAttribute("userId"));
            response.put("permissions", request.getAttribute("permissions"));
            response.put("received_data", body);

            return ResponseEntity.ok(response);
        }
    }
} 