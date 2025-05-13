package com.auth.edgegrid;

import org.springframework.http.*;
import org.springframework.web.client.RestTemplate;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.stream.Collectors;

public class EdgeGridClient {
    private final String baseUrl;
    private final String clientToken;
    private final String clientSecret;
    private final String accessToken;
    private final String host;
    private final RestTemplate restTemplate;

    public EdgeGridClient(String baseUrl, String clientToken, String clientSecret, String accessToken, String host) {
        this.baseUrl = baseUrl;
        this.clientToken = clientToken;
        this.clientSecret = clientSecret;
        this.accessToken = accessToken;
        this.host = host;
        this.restTemplate = new RestTemplate();
    }

    public Map<String, Object> callSecureEndpoint(String method, Map<String, Object> body) {
        try {
            String timestamp = String.valueOf(System.currentTimeMillis() / 1000);
            String nonce = UUID.randomUUID().toString();

            // Create headers
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.set("Host", host);

            // Generate signature
            String signature = generateSignature(
                method,
                baseUrl + "/api/secure",
                headers,
                body != null ? new org.json.JSONObject(body).toString().getBytes(StandardCharsets.UTF_8) : null,
                timestamp,
                nonce
            );

            // Add authorization header
            String authHeader = String.format(
                "EG1-HMAC-SHA256 client_token=%s;access_token=%s;timestamp=%s;nonce=%s;signature=%s",
                clientToken, accessToken, timestamp, nonce, signature
            );
            headers.set("Authorization", authHeader);

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

    private String generateSignature(String method, String url, HttpHeaders headers, byte[] body, String timestamp, String nonce) {
        try {
            // Parse URL
            URI uri = new URI(url);
            String path = uri.getPath();
            String query = uri.getQuery();

            // Create data to sign
            List<String> dataToSign = Arrays.asList(
                method,
                "https",
                host,
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
            byte[] signingKey = getSigningKey(timestamp);

            // Generate signature
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(signingKey, "HmacSHA256"));
            byte[] signatureBytes = mac.doFinal(dataToSignStr.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(signatureBytes);

        } catch (Exception e) {
            throw new RuntimeException("Failed to generate signature", e);
        }
    }

    private String getCanonicalHeaders(HttpHeaders headers) {
        return headers.entrySet().stream()
            .filter(entry -> entry.getKey().toLowerCase().equals("content-type") || 
                           entry.getKey().toLowerCase().equals("host"))
            .sorted(Map.Entry.comparingByKey())
            .map(entry -> entry.getKey().toLowerCase() + ":" + entry.getValue().get(0))
            .collect(Collectors.joining("\t"));
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

    private byte[] getSigningKey(String timestamp) {
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

    public static void main(String[] args) {
        EdgeGridClient client = new EdgeGridClient(
            "http://localhost:8091",
            "client_token",
            "client_secret_123",
            "access_token_123",
            "akab-xxxxx.luna.akamaiapis.net"
        );

        // Test GET request
        Map<String, Object> getResponse = client.callSecureEndpoint("GET", null);
        System.out.println("GET Response: " + getResponse);

        // Test POST request
        Map<String, Object> postBody = new HashMap<>();
        postBody.put("message", "Hello from EdgeGrid client!");
        Map<String, Object> postResponse = client.callSecureEndpoint("POST", postBody);
        System.out.println("POST Response: " + postResponse);
    }
} 