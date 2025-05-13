package com.auth.basic;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;
import java.util.Base64;
import java.util.Map;

public class BasicAuthClient {
    private final String baseUrl;
    private final String username;
    private final String password;
    private final RestTemplate restTemplate;

    public BasicAuthClient(String baseUrl) {
        this.baseUrl = baseUrl;
        this.username = "admin";
        this.password = "password123";
        this.restTemplate = new RestTemplate();
    }

    private String getAuthHeader() {
        String credentials = username + ":" + password;
        String encodedCredentials = Base64.getEncoder().encodeToString(credentials.getBytes());
        return "Basic " + encodedCredentials;
    }

    public void callSecureEndpoint() {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.set("Authorization", getAuthHeader());

            HttpEntity<?> requestEntity = new HttpEntity<>(headers);
            ResponseEntity<Map> response = restTemplate.exchange(
                baseUrl + "/api/secure",
                HttpMethod.GET,
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
        BasicAuthClient client = new BasicAuthClient("http://localhost:8081");
        System.out.println("Testing Basic Authentication...");
        client.callSecureEndpoint();
    }
} 