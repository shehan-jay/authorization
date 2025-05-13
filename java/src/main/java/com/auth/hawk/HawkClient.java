package com.auth.hawk;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class HawkClient {
    private final String baseUrl;
    private final String hawkId;
    private final String hawkKey;
    private final String algorithm;
    private final RestTemplate restTemplate;

    public HawkClient(String baseUrl) {
        this.baseUrl = baseUrl;
        this.hawkId = "hawk_id_1";
        this.hawkKey = "hawk_key_1";
        this.algorithm = "HmacSHA256";
        this.restTemplate = new RestTemplate();
    }

    private String generateMac(String timestamp, String nonce, String method, String uri,
                             String host, String port, String payloadHash) throws Exception {
        String normalized = String.format("hawk.1.header\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n\n",
            timestamp, nonce, method, uri, host, port, payloadHash != null ? payloadHash : "");

        Mac mac = Mac.getInstance(algorithm);
        SecretKeySpec secretKey = new SecretKeySpec(
            hawkKey.getBytes(StandardCharsets.UTF_8),
            algorithm
        );
        mac.init(secretKey);
        byte[] macBytes = mac.doFinal(normalized.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(macBytes);
    }

    private String calculatePayloadHash(String payload) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(payload.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(hash);
    }

    public void callSecureEndpoint(String method, Map<String, Object> data) {
        try {
            String url = baseUrl + "/api/secure";
            String timestamp = String.valueOf(System.currentTimeMillis() / 1000);
            String nonce = UUID.randomUUID().toString();
            String payloadHash = null;

            if (data != null) {
                String jsonPayload = new com.fasterxml.jackson.databind.ObjectMapper()
                    .writeValueAsString(data);
                payloadHash = calculatePayloadHash(jsonPayload);
            }

            String mac = generateMac(
                timestamp,
                nonce,
                method,
                "/api/secure",
                "localhost",
                "8080",
                payloadHash
            );

            HttpHeaders headers = new HttpHeaders();
            StringBuilder hawkHeader = new StringBuilder()
                .append("Hawk id=\"").append(hawkId).append("\", ")
                .append("ts=\"").append(timestamp).append("\", ")
                .append("nonce=\"").append(nonce).append("\", ")
                .append("mac=\"").append(mac).append("\"");

            if (payloadHash != null) {
                hawkHeader.append(", hash=\"").append(payloadHash).append("\"");
            }

            headers.set("Authorization", hawkHeader.toString());

            HttpEntity<?> requestEntity = new HttpEntity<>(data, headers);
            ResponseEntity<Map> response = restTemplate.exchange(
                url,
                HttpMethod.valueOf(method),
                requestEntity,
                Map.class
            );

            System.out.println("Status Code: " + response.getStatusCode());
            System.out.println("Response: " + response.getBody());
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        HawkClient client = new HawkClient("http://localhost:8080");

        // Test GET request
        System.out.println("Testing GET request...");
        client.callSecureEndpoint("GET", null);

        // Test POST request with data
        System.out.println("\nTesting POST request...");
        Map<String, Object> data = new HashMap<>();
        data.put("message", "Hello, Hawk!");
        client.callSecureEndpoint("POST", data);
    }
} 