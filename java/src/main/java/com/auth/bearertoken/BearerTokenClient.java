package com.auth.bearertoken;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;
import java.util.Map;

@SpringBootApplication
public class BearerTokenClient implements CommandLineRunner {

    private static final String BASE_URL = "http://localhost:8080";
    private String token;

    public static void main(String[] args) {
        SpringApplication.run(BearerTokenClient.class, args);
    }

    @Override
    public void run(String... args) {
        RestTemplate restTemplate = new RestTemplate();

        // Get token
        System.out.println("Getting token...");
        ResponseEntity<Map> tokenResponse = restTemplate.postForEntity(
            BASE_URL + "/api/token", null, Map.class);
        token = (String) tokenResponse.getBody().get("access_token");
        System.out.println("Token received: " + token);

        // Test with valid token
        System.out.println("\nTesting with valid token:");
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + token);
        HttpEntity<?> entity = new HttpEntity<>(headers);

        ResponseEntity<Map> response = restTemplate.exchange(
            BASE_URL + "/api/secure",
            HttpMethod.GET,
            entity,
            Map.class
        );
        System.out.println("Status Code: " + response.getStatusCode());
        System.out.println("Response: " + response.getBody());

        // Test with invalid token
        System.out.println("\nTesting with invalid token:");
        headers.set("Authorization", "Bearer invalid_token");
        entity = new HttpEntity<>(headers);

        try {
            response = restTemplate.exchange(
                BASE_URL + "/api/secure",
                HttpMethod.GET,
                entity,
                Map.class
            );
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
    }
} 