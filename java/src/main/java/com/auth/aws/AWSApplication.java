package com.auth.aws;

import com.auth.base.BaseAuth;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import javax.servlet.http.HttpServletRequest;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@SpringBootApplication
public class AWSApplication {
    public static void main(String[] args) {
        SpringApplication.run(AWSApplication.class, args);
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
                .addFilter(new AWSAuth());
        }
    }

    public static class AWSAuth extends BaseAuth {
        private static final Map<String, AWSCredentials> CREDENTIALS = new ConcurrentHashMap<>();
        private static final long MAX_TIMESTAMP_AGE = 300; // 5 minutes in seconds

        static {
            CREDENTIALS.put("AKIAIOSFODNN7EXAMPLE", new AWSCredentials(
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "us-east-1",
                "example"
            ));
        }

        public AWSAuth() {
            setPort(8088);
        }

        @Override
        protected boolean authenticate(HttpServletRequest request) {
            String authHeader = request.getHeader("Authorization");
            if (authHeader == null || !authHeader.startsWith("AWS4-HMAC-SHA256")) {
                return false;
            }

            try {
                // Parse authorization header
                Map<String, String> authParams = parseAuthHeader(authHeader);
                
                // Extract credentials
                String accessKey = authParams.get("Credential").split("/")[0];
                AWSCredentials credentials = CREDENTIALS.get(accessKey);
                if (credentials == null) {
                    return false;
                }

                // Verify timestamp
                String amzDate = request.getHeader("x-amz-date");
                if (!isValidTimestamp(amzDate)) {
                    return false;
                }

                // Get request details
                String method = request.getMethod();
                String path = request.getRequestURI();
                Map<String, String> queryParams = getQueryParams(request);
                Map<String, String> headers = getHeaders(request);
                String body = getRequestBody(request);

                // Generate expected signature
                String expectedSignature = generateSignature(
                    credentials,
                    method,
                    path,
                    queryParams,
                    headers,
                    body,
                    amzDate
                );

                // Verify signature
                return authParams.get("Signature").equals(expectedSignature);
            } catch (Exception e) {
                return false;
            }
        }

        private Map<String, String> parseAuthHeader(String header) {
            Map<String, String> params = new HashMap<>();
            String[] parts = header.substring("AWS4-HMAC-SHA256 ".length()).split(", ");
            for (String part : parts) {
                String[] keyValue = part.split("=", 2);
                params.put(keyValue[0], keyValue[1]);
            }
            return params;
        }

        private boolean isValidTimestamp(String amzDate) {
            try {
                LocalDateTime requestTime = LocalDateTime.parse(amzDate, 
                    DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'"));
                LocalDateTime now = LocalDateTime.now();
                return Math.abs(java.time.Duration.between(requestTime, now).getSeconds()) <= MAX_TIMESTAMP_AGE;
            } catch (Exception e) {
                return false;
            }
        }

        private Map<String, String> getQueryParams(HttpServletRequest request) {
            Map<String, String> params = new HashMap<>();
            String queryString = request.getQueryString();
            if (queryString != null) {
                String[] pairs = queryString.split("&");
                for (String pair : pairs) {
                    String[] keyValue = pair.split("=");
                    if (keyValue.length == 2) {
                        params.put(keyValue[0], keyValue[1]);
                    }
                }
            }
            return params;
        }

        private Map<String, String> getHeaders(HttpServletRequest request) {
            Map<String, String> headers = new HashMap<>();
            Enumeration<String> headerNames = request.getHeaderNames();
            while (headerNames.hasMoreElements()) {
                String name = headerNames.nextElement();
                headers.put(name.toLowerCase(), request.getHeader(name));
            }
            return headers;
        }

        private String getRequestBody(HttpServletRequest request) throws Exception {
            return request.getReader().lines().collect(Collectors.joining());
        }

        private String generateSignature(AWSCredentials credentials, String method, String path,
                                      Map<String, String> queryParams, Map<String, String> headers,
                                      String body, String amzDate) throws Exception {
            // Create canonical request
            String canonicalHeaders = headers.entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .map(e -> e.getKey() + ":" + e.getValue().trim())
                .collect(Collectors.joining("\n"));

            String signedHeaders = headers.keySet().stream()
                .sorted()
                .collect(Collectors.joining(";"));

            String payloadHash = MessageDigest.getInstance("SHA-256")
                .digest((body != null ? body : "").getBytes(StandardCharsets.UTF_8))
                .toString();

            String canonicalRequest = String.join("\n",
                method,
                path,
                queryParams.entrySet().stream()
                    .sorted(Map.Entry.comparingByKey())
                    .map(e -> e.getKey() + "=" + e.getValue())
                    .collect(Collectors.joining("&")),
                canonicalHeaders,
                signedHeaders,
                payloadHash
            );

            // Create string to sign
            String dateStamp = amzDate.substring(0, 8);
            String credentialScope = String.format("%s/%s/%s/aws4_request",
                dateStamp, credentials.getRegion(), credentials.getService());

            String stringToSign = String.join("\n",
                "AWS4-HMAC-SHA256",
                amzDate,
                credentialScope,
                MessageDigest.getInstance("SHA-256")
                    .digest(canonicalRequest.getBytes(StandardCharsets.UTF_8))
                    .toString()
            );

            // Calculate signing key
            byte[] kDate = sign(("AWS4" + credentials.getSecretKey()).getBytes(StandardCharsets.UTF_8), dateStamp);
            byte[] kRegion = sign(kDate, credentials.getRegion());
            byte[] kService = sign(kRegion, credentials.getService());
            byte[] kSigning = sign(kService, "aws4_request");

            // Calculate signature
            return bytesToHex(sign(kSigning, stringToSign));
        }

        private byte[] sign(byte[] key, String msg) throws Exception {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(msg.getBytes(StandardCharsets.UTF_8));
        }

        private String bytesToHex(byte[] bytes) {
            StringBuilder result = new StringBuilder();
            for (byte b : bytes) {
                result.append(String.format("%02x", b));
            }
            return result.toString();
        }
    }

    public static class AWSCredentials {
        private final String secretKey;
        private final String region;
        private final String service;

        public AWSCredentials(String secretKey, String region, String service) {
            this.secretKey = secretKey;
            this.region = region;
            this.service = service;
        }

        public String getSecretKey() {
            return secretKey;
        }

        public String getRegion() {
            return region;
        }

        public String getService() {
            return service;
        }
    }

    @RestController
    @RequestMapping("/api")
    public static class SecureController {
        @GetMapping("/secure")
        public Map<String, String> secureEndpoint() {
            Map<String, String> response = new HashMap<>();
            response.put("message", "This is a secure endpoint that requires AWS Signature authentication");
            response.put("status", "success");
            return response;
        }

        @PostMapping("/secure")
        public Map<String, String> securePostEndpoint(@RequestBody Map<String, Object> body) {
            Map<String, String> response = new HashMap<>();
            response.put("message", "This is a secure POST endpoint that requires AWS Signature authentication");
            response.put("status", "success");
            response.put("received_data", body.toString());
            return response;
        }
    }
} 