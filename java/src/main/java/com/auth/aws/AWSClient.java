package com.auth.aws;

import org.springframework.http.*;
import org.springframework.web.client.RestTemplate;
import org.json.JSONObject;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

public class AWSClient {
    private final String baseUrl;
    private final String accessKey;
    private final String secretKey;
    private final String region;
    private final String service;
    private final RestTemplate restTemplate;

    public AWSClient(String baseUrl, String accessKey, String secretKey, String region, String service) {
        this.baseUrl = baseUrl;
        this.accessKey = accessKey;
        this.secretKey = secretKey;
        this.region = region;
        this.service = service;
        this.restTemplate = new RestTemplate();
    }

    private String generateSignature(String method, String path, Map<String, String> queryParams,
                                   Map<String, String> headers, String body, String amzDate) throws Exception {
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
            dateStamp, region, service);

        String stringToSign = String.join("\n",
            "AWS4-HMAC-SHA256",
            amzDate,
            credentialScope,
            MessageDigest.getInstance("SHA-256")
                .digest(canonicalRequest.getBytes(StandardCharsets.UTF_8))
                .toString()
        );

        // Calculate signing key
        byte[] kDate = sign(("AWS4" + secretKey).getBytes(StandardCharsets.UTF_8), dateStamp);
        byte[] kRegion = sign(kDate, region);
        byte[] kService = sign(kRegion, service);
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

    public ResponseEntity<String> callSecureEndpoint(String method, Map<String, Object> body) {
        try {
            // Generate timestamp
            String amzDate = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'"));

            // Prepare headers
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.set("x-amz-date", amzDate);

            // Prepare request body
            String requestBody = body != null ? new org.json.JSONObject(body).toString() : null;

            // Generate signature
            String signature = generateSignature(
                method,
                "/api/secure",
                Collections.emptyMap(),
                headers.toSingleValueMap(),
                requestBody,
                amzDate
            );

            // Create authorization header
            String dateStamp = amzDate.substring(0, 8);
            String credentialScope = String.format("%s/%s/%s/aws4_request",
                dateStamp, region, service);
            String authorization = String.format("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
                accessKey, credentialScope, "content-type;host;x-amz-date", signature);

            headers.set("Authorization", authorization);

            // Make request
            HttpEntity<String> requestEntity = new HttpEntity<>(requestBody, headers);
            return restTemplate.exchange(
                baseUrl + "/api/secure",
                method.equals("GET") ? HttpMethod.GET : HttpMethod.POST,
                requestEntity,
                String.class
            );
        } catch (Exception e) {
            throw new RuntimeException("Failed to call secure endpoint: " + e.getMessage(), e);
        }
    }

    public static void main(String[] args) {
        AWSClient client = new AWSClient(
            "http://localhost:8088",
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "us-east-1",
            "example"
        );

        // Test GET request
        ResponseEntity<String> getResponse = client.callSecureEndpoint("GET", null);
        System.out.println("GET Response Status: " + getResponse.getStatusCode());
        System.out.println("GET Response Body: " + getResponse.getBody());

        // Test POST request
        Map<String, Object> postBody = new HashMap<>();
        postBody.put("message", "Hello from AWS Signature client!");
        ResponseEntity<String> postResponse = client.callSecureEndpoint("POST", postBody);
        System.out.println("POST Response Status: " + postResponse.getStatusCode());
        System.out.println("POST Response Body: " + postResponse.getBody());
    }
} 