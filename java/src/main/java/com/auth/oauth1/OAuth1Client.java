package com.auth.oauth1;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.TreeMap;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

public class OAuth1Client {
    private final String baseUrl;
    private final String consumerKey;
    private final String consumerSecret;
    private String requestToken;
    private String requestTokenSecret;
    private String accessToken;
    private String accessTokenSecret;
    private final RestTemplate restTemplate;

    public OAuth1Client(String baseUrl) {
        this.baseUrl = baseUrl;
        this.consumerKey = "consumer_key_1";
        this.consumerSecret = "consumer_secret_1";
        this.restTemplate = new RestTemplate();
    }

    private String generateNonce() {
        byte[] nonceBytes = new byte[32];
        new Random().nextBytes(nonceBytes);
        return Base64.getEncoder().encodeToString(nonceBytes);
    }

    private String generateSignature(String method, String url, Map<String, String> params, String tokenSecret) throws Exception {
        // Sort parameters
        TreeMap<String, String> sortedParams = new TreeMap<>(params);
        
        // Create parameter string
        StringBuilder paramString = new StringBuilder();
        for (Map.Entry<String, String> entry : sortedParams.entrySet()) {
            if (paramString.length() > 0) {
                paramString.append("&");
            }
            paramString.append(URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8.toString()))
                      .append("=")
                      .append(URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8.toString()));
        }

        // Create signature base string
        String baseString = method.toUpperCase() + "&" +
                          URLEncoder.encode(url, StandardCharsets.UTF_8.toString()) + "&" +
                          URLEncoder.encode(paramString.toString(), StandardCharsets.UTF_8.toString());

        // Create signing key
        String signingKey = URLEncoder.encode(consumerSecret, StandardCharsets.UTF_8.toString()) + "&";
        if (tokenSecret != null) {
            signingKey += URLEncoder.encode(tokenSecret, StandardCharsets.UTF_8.toString());
        }

        // Generate signature
        Mac mac = Mac.getInstance("HmacSHA1");
        SecretKeySpec secretKeySpec = new SecretKeySpec(signingKey.getBytes(StandardCharsets.UTF_8), "HmacSHA1");
        mac.init(secretKeySpec);
        byte[] signatureBytes = mac.doFinal(baseString.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(signatureBytes);
    }

    public boolean getRequestToken() {
        try {
            Map<String, String> params = new HashMap<>();
            params.put("oauth_consumer_key", consumerKey);
            params.put("oauth_nonce", generateNonce());
            params.put("oauth_signature_method", "HMAC-SHA1");
            params.put("oauth_timestamp", String.valueOf(System.currentTimeMillis() / 1000));
            params.put("oauth_version", "1.0");

            String signature = generateSignature("POST", baseUrl + "/oauth/request_token", params, null);
            params.put("oauth_signature", signature);

            HttpHeaders headers = new HttpHeaders();
            headers.set("Authorization", "OAuth " + buildOAuthHeader(params));

            ResponseEntity<Map> response = restTemplate.exchange(
                baseUrl + "/oauth/request_token",
                HttpMethod.POST,
                new HttpEntity<>(headers),
                Map.class
            );

            if (response.getStatusCode().is2xxSuccessful()) {
                Map<String, String> responseBody = response.getBody();
                requestToken = responseBody.get("oauth_token");
                requestTokenSecret = responseBody.get("oauth_token_secret");
                return true;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    public boolean getAccessToken() {
        if (requestToken == null) {
            System.out.println("Request token not obtained");
            return false;
        }

        try {
            Map<String, String> params = new HashMap<>();
            params.put("oauth_consumer_key", consumerKey);
            params.put("oauth_nonce", generateNonce());
            params.put("oauth_signature_method", "HMAC-SHA1");
            params.put("oauth_timestamp", String.valueOf(System.currentTimeMillis() / 1000));
            params.put("oauth_token", requestToken);
            params.put("oauth_version", "1.0");

            String signature = generateSignature("POST", baseUrl + "/oauth/access_token", params, requestTokenSecret);
            params.put("oauth_signature", signature);

            HttpHeaders headers = new HttpHeaders();
            headers.set("Authorization", "OAuth " + buildOAuthHeader(params));

            ResponseEntity<Map> response = restTemplate.exchange(
                baseUrl + "/oauth/access_token",
                HttpMethod.POST,
                new HttpEntity<>(headers),
                Map.class
            );

            if (response.getStatusCode().is2xxSuccessful()) {
                Map<String, String> responseBody = response.getBody();
                accessToken = responseBody.get("oauth_token");
                accessTokenSecret = responseBody.get("oauth_token_secret");
                return true;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    public void callSecureEndpoint() {
        if (accessToken == null) {
            System.out.println("Access token not obtained");
            return;
        }

        try {
            Map<String, String> params = new HashMap<>();
            params.put("oauth_consumer_key", consumerKey);
            params.put("oauth_nonce", generateNonce());
            params.put("oauth_signature_method", "HMAC-SHA1");
            params.put("oauth_timestamp", String.valueOf(System.currentTimeMillis() / 1000));
            params.put("oauth_token", accessToken);
            params.put("oauth_version", "1.0");

            String signature = generateSignature("GET", baseUrl + "/api/secure", params, accessTokenSecret);
            params.put("oauth_signature", signature);

            HttpHeaders headers = new HttpHeaders();
            headers.set("Authorization", "OAuth " + buildOAuthHeader(params));

            ResponseEntity<Map> response = restTemplate.exchange(
                baseUrl + "/api/secure",
                HttpMethod.GET,
                new HttpEntity<>(headers),
                Map.class
            );

            System.out.println("Status Code: " + response.getStatusCode());
            System.out.println("Response: " + response.getBody());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String buildOAuthHeader(Map<String, String> params) {
        StringBuilder header = new StringBuilder();
        for (Map.Entry<String, String> entry : params.entrySet()) {
            if (header.length() > 0) {
                header.append(", ");
            }
            header.append(entry.getKey())
                  .append("=\"")
                  .append(URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8))
                  .append("\"");
        }
        return header.toString();
    }

    public static void main(String[] args) {
        OAuth1Client client = new OAuth1Client("http://localhost:8080");

        // Get request token
        System.out.println("Getting request token...");
        if (client.getRequestToken()) {
            System.out.println("Request token obtained successfully");

            // Get access token
            System.out.println("\nGetting access token...");
            if (client.getAccessToken()) {
                System.out.println("Access token obtained successfully");

                // Call secure endpoint
                System.out.println("\nCalling secure endpoint...");
                client.callSecureEndpoint();
            } else {
                System.out.println("Failed to get access token");
            }
        } else {
            System.out.println("Failed to get request token");
        }
    }
} 