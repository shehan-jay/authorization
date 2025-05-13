package com.auth.edgegrid;

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

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@SpringBootApplication
public class EdgeGridApplication {
    public static void main(String[] args) {
        SpringApplication.run(EdgeGridApplication.class, args);
    }

    @Configuration
    @EnableWebSecurity
    public static class SecurityConfig extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/api/secure/**").authenticated()
                .anyRequest().permitAll()
                .and()
                .addFilterBefore(edgeGridAuthFilter(), UsernamePasswordAuthenticationFilter.class);
        }

        @Bean
        public EdgeGridAuthFilter edgeGridAuthFilter() {
            return new EdgeGridAuthFilter();
        }
    }

    public static class EdgeGridAuth extends BaseAuth {
        private final Map<String, EdgeGridCredentials> credentials = new ConcurrentHashMap<>();

        public EdgeGridAuth() {
            // Add test credentials
            credentials.put("client_token", new EdgeGridCredentials(
                "client_secret_123",
                "access_token_123",
                "akab-xxxxx.luna.akamaiapis.net"
            ));
        }

        public boolean authenticate(HttpServletRequest request) {
            String authHeader = request.getHeader("Authorization");
            if (authHeader == null || !authHeader.startsWith("EG1-HMAC-SHA256")) {
                return false;
            }

            try {
                // Parse authorization header
                Map<String, String> authParts = parseAuthHeader(authHeader);
                String clientToken = authParts.get("client_token");
                String accessToken = authParts.get("access_token");
                String timestamp = authParts.get("timestamp");
                String nonce = authParts.get("nonce");
                String signature = authParts.get("signature");

                if (!validateAuthParts(clientToken, accessToken, timestamp, nonce, signature)) {
                    return false;
                }

                // Verify timestamp is within 5 minutes
                if (Math.abs(System.currentTimeMillis() / 1000 - Long.parseLong(timestamp)) > 300) {
                    return false;
                }

                // Get credentials
                EdgeGridCredentials creds = credentials.get(clientToken);
                if (creds == null) {
                    return false;
                }

                // Generate expected signature
                String expectedSignature = generateSignature(
                    request.getMethod(),
                    request.getRequestURI(),
                    request.getQueryString(),
                    getRequestHeaders(request),
                    getRequestBody(request),
                    clientToken,
                    accessToken,
                    timestamp,
                    nonce,
                    creds.clientSecret
                );

                // Compare signatures
                if (!signature.equals(expectedSignature)) {
                    return false;
                }

                // Store client info in request
                request.setAttribute("clientToken", clientToken);
                request.setAttribute("accessToken", accessToken);
                return true;

            } catch (Exception e) {
                e.printStackTrace();
                return false;
            }
        }

        private Map<String, String> parseAuthHeader(String authHeader) {
            Map<String, String> parts = new HashMap<>();
            String[] items = authHeader.substring("EG1-HMAC-SHA256 ".length()).split(";");
            for (String item : items) {
                String[] keyValue = item.split("=");
                parts.put(keyValue[0], keyValue[1]);
            }
            return parts;
        }

        private boolean validateAuthParts(String clientToken, String accessToken, String timestamp, String nonce, String signature) {
            return clientToken != null && accessToken != null && timestamp != null && nonce != null && signature != null;
        }

        private String generateSignature(String method, String path, String query, Map<String, String> headers, byte[] body,
                                      String clientToken, String accessToken, String timestamp, String nonce, String clientSecret) {
            try {
                // Create data to sign
                List<String> dataToSign = Arrays.asList(
                    method,
                    "https",
                    headers.getOrDefault("host", ""),
                    path + (query != null ? "?" + query : ""),
                    getCanonicalHeaders(headers),
                    getContentHash(body),
                    clientToken,
                    accessToken,
                    timestamp,
                    nonce
                );
                String dataToSignStr = String.join("\t", dataToSign);

                // Create signing key
                byte[] signingKey = getSigningKey(clientSecret, timestamp);

                // Generate signature
                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(new SecretKeySpec(signingKey, "HmacSHA256"));
                byte[] signatureBytes = mac.doFinal(dataToSignStr.getBytes(StandardCharsets.UTF_8));
                return bytesToHex(signatureBytes);

            } catch (NoSuchAlgorithmException | InvalidKeyException e) {
                throw new RuntimeException("Failed to generate signature", e);
            }
        }

        private String getCanonicalHeaders(Map<String, String> headers) {
            List<String> canonicalHeaders = new ArrayList<>();
            for (Map.Entry<String, String> entry : headers.entrySet()) {
                String key = entry.getKey().toLowerCase();
                if (key.equals("content-type") || key.equals("host")) {
                    canonicalHeaders.add(key + ":" + entry.getValue());
                }
            }
            Collections.sort(canonicalHeaders);
            return String.join("\t", canonicalHeaders);
        }

        private String getContentHash(byte[] body) {
            try {
                java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
                byte[] hash = md.digest(body != null ? body : new byte[0]);
                return bytesToHex(hash);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException("Failed to generate content hash", e);
            }
        }

        private byte[] getSigningKey(String clientSecret, String timestamp) {
            try {
                SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMdd");
                sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
                String date = sdf.format(new Date(Long.parseLong(timestamp) * 1000));

                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(new SecretKeySpec(clientSecret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
                return mac.doFinal(date.getBytes(StandardCharsets.UTF_8));
            } catch (NoSuchAlgorithmException | InvalidKeyException e) {
                throw new RuntimeException("Failed to generate signing key", e);
            }
        }

        private String bytesToHex(byte[] bytes) {
            StringBuilder result = new StringBuilder();
            for (byte b : bytes) {
                result.append(String.format("%02x", b));
            }
            return result.toString();
        }

        private Map<String, String> getRequestHeaders(HttpServletRequest request) {
            Map<String, String> headers = new HashMap<>();
            Collections.list(request.getHeaderNames()).forEach(name -> 
                headers.put(name.toLowerCase(), request.getHeader(name)));
            return headers;
        }

        private byte[] getRequestBody(HttpServletRequest request) {
            try {
                return request.getInputStream().readAllBytes();
            } catch (IOException e) {
                return new byte[0];
            }
        }
    }

    public static class EdgeGridCredentials {
        public final String clientSecret;
        public final String accessToken;
        public final String host;

        public EdgeGridCredentials(String clientSecret, String accessToken, String host) {
            this.clientSecret = clientSecret;
            this.accessToken = accessToken;
            this.host = host;
        }
    }

    public static class EdgeGridAuthFilter extends OncePerRequestFilter {
        private final EdgeGridAuth auth = new EdgeGridAuth();

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws ServletException, IOException {
            if (!auth.authenticate(request)) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("Invalid EdgeGrid authentication");
                return;
            }
            chain.doFilter(request, response);
        }
    }

    @RestController
    @RequestMapping("/api")
    public static class SecureController {
        @GetMapping("/secure")
        public ResponseEntity<Map<String, Object>> secureGet(HttpServletRequest request) {
            Map<String, Object> response = new HashMap<>();
            response.put("message", "This is a secure endpoint that requires Akamai EdgeGrid authentication");
            response.put("status", "success");
            response.put("client_token", request.getAttribute("clientToken"));
            response.put("access_token", request.getAttribute("accessToken"));

            return ResponseEntity.ok(response);
        }

        @PostMapping("/secure")
        public ResponseEntity<Map<String, Object>> securePost(
                HttpServletRequest request,
                @RequestBody(required = false) Map<String, Object> body) {
            Map<String, Object> response = new HashMap<>();
            response.put("message", "This is a secure endpoint that requires Akamai EdgeGrid authentication");
            response.put("status", "success");
            response.put("client_token", request.getAttribute("clientToken"));
            response.put("access_token", request.getAttribute("accessToken"));
            response.put("received_data", body);

            return ResponseEntity.ok(response);
        }
    }
} 