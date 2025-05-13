package com.auth.apikey;

import org.springframework.http.*;
import org.springframework.web.client.RestTemplate;
import java.util.*;

public class APIKeyClient {
    private final String baseUrl;
    private final String apiKey;
    private final RestTemplate restTemplate;

    public APIKeyClient(String baseUrl, String apiKey) {
        this.baseUrl = baseUrl;
        this.apiKey = apiKey;
        this.restTemplate = new RestTemplate();
    }

    public Map<String, Object> createApiKey(String userId, List<String> permissions, int expiresInDays) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        Map<String, Object> requestBody = new HashMap<>();
        requestBody.put("user_id", userId);
        requestBody.put("permissions", permissions);
        requestBody.put("expires_in_days", expiresInDays);

        HttpEntity<Map<String, Object>> requestEntity = new HttpEntity<>(requestBody, headers);
        ResponseEntity<Map> response = restTemplate.exchange(
            baseUrl + "/api/keys",
            HttpMethod.POST,
            requestEntity,
            Map.class
        );

        return response.getBody();
    }

    public Map<String, Object> callSecureEndpoint(String method, Map<String, Object> body) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("X-API-Key", apiKey);

        HttpEntity<Map<String, Object>> requestEntity = new HttpEntity<>(body, headers);
        ResponseEntity<Map> response = restTemplate.exchange(
            baseUrl + "/api/secure",
            method.equals("GET") ? HttpMethod.GET : HttpMethod.POST,
            requestEntity,
            Map.class
        );

        return response.getBody();
    }

    public static void main(String[] args) {
        APIKeyClient client = new APIKeyClient(
            "http://localhost:8090",
            "sk_test_51H7qXKJw3Jw3Jw3Jw3Jw3Jw3"
        );

        // Test GET request
        Map<String, Object> getResponse = client.callSecureEndpoint("GET", null);
        System.out.println("GET Response: " + getResponse);

        // Test POST request
        Map<String, Object> postBody = new HashMap<>();
        postBody.put("message", "Hello from API Key client!");
        Map<String, Object> postResponse = client.callSecureEndpoint("POST", postBody);
        System.out.println("POST Response: " + postResponse);
    }
} 