package com.auth.noauth;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.ResponseEntity;
import java.util.Map;

@SpringBootApplication
public class PublicClient implements CommandLineRunner {

    public static void main(String[] args) {
        SpringApplication.run(PublicClient.class, args);
    }

    @Override
    public void run(String... args) {
        RestTemplate restTemplate = new RestTemplate();
        String url = "http://localhost:8080/api/public";
        
        ResponseEntity<Map> response = restTemplate.getForEntity(url, Map.class);
        System.out.println("Status Code: " + response.getStatusCode());
        System.out.println("Response: " + response.getBody());
    }
} 