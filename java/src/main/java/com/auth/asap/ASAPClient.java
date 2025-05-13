package com.auth.asap;

import org.springframework.http.*;
import org.springframework.web.client.RestTemplate;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;

public class ASAPClient {
    private final String baseUrl;
    private final String issuer;
    private final String audience;
    private final String subject;
    private final PrivateKey privateKey;
    private final RestTemplate restTemplate;

    public ASAPClient(String baseUrl, String issuer, String audience, String subject, String privateKeyPath) {
        this.baseUrl = baseUrl;
        this.issuer = issuer;
        this.audience = audience;
        this.subject = subject;
        this.privateKey = loadPrivateKey(privateKeyPath);
        this.restTemplate = new RestTemplate();
    }

    private PrivateKey loadPrivateKey(String privateKeyPath) {
        try {
            byte[] keyBytes = Files.readAllBytes(new File(privateKeyPath).toPath());
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            throw new RuntimeException("Failed to load private key", e);
        }
    }

    public Map<String, String> generateToken(String issuer, String audience, String subject, long expiresIn) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        Map<String, String> request = new HashMap<>();
        request.put("issuer", issuer);
        request.put("audience", audience);
        request.put("subject", subject);
        request.put("expires_in", String.valueOf(expiresIn));

        HttpEntity<Map<String, String>> requestEntity = new HttpEntity<>(request, headers);
        ResponseEntity<Map> response = restTemplate.postForEntity(
            baseUrl + "/api/token",
            requestEntity,
            Map.class
        );

        return response.getBody();
    }

    public Map<String, Object> callSecureEndpoint(String method, Map<String, Object> body) {
        try {
            // Generate token
            String token = generateToken();

            // Create headers
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.setBearerAuth(token);

            // Make request
            HttpEntity<Map<String, Object>> requestEntity = new HttpEntity<>(body, headers);
            ResponseEntity<Map> response = restTemplate.exchange(
                baseUrl + "/api/secure",
                method.equals("GET") ? HttpMethod.GET : HttpMethod.POST,
                requestEntity,
                Map.class
            );

            return response.getBody();

        } catch (Exception e) {
            throw new RuntimeException("Failed to call secure endpoint: " + e.getMessage(), e);
        }
    }

    private String generateToken() {
        Date now = new Date();
        Date expiration = new Date(now.getTime() + 3600 * 1000); // 1 hour

        return Jwts.builder()
            .setIssuer(issuer)
            .setSubject(subject)
            .setAudience(audience)
            .setIssuedAt(now)
            .setExpiration(expiration)
            .setId(now.getTime() + "-" + subject)
            .signWith(privateKey, SignatureAlgorithm.RS256)
            .compact();
    }

    public static void main(String[] args) {
        ASAPClient client = new ASAPClient(
            "http://localhost:8092",
            "service.example.com",
            "api.example.com",
            "test-service",
            "path/to/private.key"
        );

        // Test GET request
        Map<String, Object> getResponse = client.callSecureEndpoint("GET", null);
        System.out.println("GET Response: " + getResponse);

        // Test POST request
        Map<String, Object> postBody = new HashMap<>();
        postBody.put("message", "Hello from ASAP client!");
        Map<String, Object> postResponse = client.callSecureEndpoint("POST", postBody);
        System.out.println("POST Response: " + postResponse);
    }
} 