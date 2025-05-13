package com.auth.hawk;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@SpringBootApplication
public class HawkApplication {
    public static void main(String[] args) {
        SpringApplication.run(HawkApplication.class, args);
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
                .antMatchers("/api/secure/**").authenticated()
                .anyRequest().permitAll()
                .and()
                .addFilter(new HawkAuthenticationFilter());
        }
    }

    @RestController
    @RequestMapping("/api/secure")
    public static class SecureController {
        @GetMapping
        public Map<String, String> secureEndpoint() {
            Map<String, String> response = new HashMap<>();
            response.put("message", "This is a secure endpoint that requires Hawk authentication");
            response.put("status", "success");
            return response;
        }

        @PostMapping
        public Map<String, String> securePostEndpoint(@RequestBody Map<String, Object> body) {
            Map<String, String> response = new HashMap<>();
            response.put("message", "This is a secure POST endpoint that requires Hawk authentication");
            response.put("status", "success");
            response.put("received_data", body.toString());
            return response;
        }
    }

    public static class HawkAuthenticationFilter extends OncePerRequestFilter {
        private static final Map<String, HawkCredentials> CREDENTIALS = new ConcurrentHashMap<>();
        private static final long MAX_TIMESTAMP_AGE = 60; // seconds

        static {
            CREDENTIALS.put("hawk_id_1", new HawkCredentials("hawk_key_1", "HmacSHA256"));
        }

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
                throws ServletException, IOException {
            String authHeader = request.getHeader("Authorization");
            if (authHeader == null || !authHeader.startsWith("Hawk ")) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("{\"message\": \"Hawk authentication required\"}");
                return;
            }

            try {
                // Parse Hawk parameters
                Map<String, String> hawkParams = parseHawkHeader(authHeader.substring(5));

                // Verify required parameters
                if (!hawkParams.containsKey("id") || !hawkParams.containsKey("ts") ||
                    !hawkParams.containsKey("nonce") || !hawkParams.containsKey("mac")) {
                    response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                    response.getWriter().write("{\"message\": \"Missing required Hawk parameters\"}");
                    return;
                }

                // Verify credentials
                HawkCredentials credentials = CREDENTIALS.get(hawkParams.get("id"));
                if (credentials == null) {
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.getWriter().write("{\"message\": \"Invalid Hawk ID\"}");
                    return;
                }

                // Verify timestamp
                long timestamp = Long.parseLong(hawkParams.get("ts"));
                if (Math.abs(System.currentTimeMillis() / 1000 - timestamp) > MAX_TIMESTAMP_AGE) {
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.getWriter().write("{\"message\": \"Request expired\"}");
                    return;
                }

                // Calculate payload hash if present
                String payloadHash = null;
                if (request.getContentLength() > 0) {
                    String body = request.getReader().lines().collect(Collectors.joining());
                    payloadHash = calculatePayloadHash(body);
                }

                // Calculate expected MAC
                String expectedMac = calculateMac(
                    credentials,
                    hawkParams.get("ts"),
                    hawkParams.get("nonce"),
                    request.getMethod(),
                    request.getRequestURI(),
                    request.getServerName(),
                    String.valueOf(request.getServerPort()),
                    payloadHash
                );

                // Verify MAC
                if (!hawkParams.get("mac").equals(expectedMac)) {
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.getWriter().write("{\"message\": \"Invalid MAC\"}");
                    return;
                }

                filterChain.doFilter(request, response);
            } catch (Exception e) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("{\"message\": \"Authentication failed: " + e.getMessage() + "\"}");
            }
        }

        private Map<String, String> parseHawkHeader(String header) {
            Map<String, String> params = new HashMap<>();
            for (String param : header.split(", ")) {
                String[] parts = param.split("=", 2);
                if (parts.length == 2) {
                    params.put(parts[0], parts[1].replace("\"", ""));
                }
            }
            return params;
        }

        private String calculatePayloadHash(String payload) throws Exception {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(payload.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        }

        private String calculateMac(HawkCredentials credentials, String timestamp, String nonce,
                                  String method, String uri, String host, String port, String payloadHash) throws Exception {
            String normalized = String.format("hawk.1.header\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n\n",
                timestamp, nonce, method, uri, host, port, payloadHash != null ? payloadHash : "");

            Mac mac = Mac.getInstance(credentials.getAlgorithm());
            SecretKeySpec secretKey = new SecretKeySpec(
                credentials.getKey().getBytes(StandardCharsets.UTF_8),
                credentials.getAlgorithm()
            );
            mac.init(secretKey);
            byte[] macBytes = mac.doFinal(normalized.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(macBytes);
        }
    }

    public static class HawkCredentials {
        private final String key;
        private final String algorithm;

        public HawkCredentials(String key, String algorithm) {
            this.key = key;
            this.algorithm = algorithm;
        }

        public String getKey() {
            return key;
        }

        public String getAlgorithm() {
            return algorithm;
        }
    }
} 