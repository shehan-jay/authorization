package com.auth.oauth2;

import org.springframework.http.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

public class OAuth2Client {
    private final String clientId;
    private final String clientSecret;
    private final String redirectUri;
    private final String authUrl;
    private final String tokenUrl;
    private final RestTemplate restTemplate;
    private String accessToken;
    private String refreshToken;
    private String scope;

    public OAuth2Client(String clientId, String clientSecret, String redirectUri, String authUrl, String tokenUrl) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.redirectUri = redirectUri;
        this.authUrl = authUrl;
        this.tokenUrl = tokenUrl;
        this.restTemplate = new RestTemplate();
    }

    public void startAuthorization() throws IOException, InterruptedException, ExecutionException {
        // Generate state parameter
        String state = java.util.UUID.randomUUID().toString();

        // Build authorization URL
        String authUrl = UriComponentsBuilder.fromHttpUrl(this.authUrl)
            .queryParam("client_id", clientId)
            .queryParam("redirect_uri", redirectUri)
            .queryParam("response_type", "code")
            .queryParam("scope", "read write")
            .queryParam("state", state)
            .build()
            .toString();

        // Start local server to receive callback
        CompletableFuture<String> codeFuture = new CompletableFuture<>();
        startCallbackServer(codeFuture);

        // Open browser for authorization
        java.awt.Desktop.getDesktop().browse(new URI(authUrl));

        // Wait for authorization code
        String code = codeFuture.get();
        if (code == null) {
            throw new RuntimeException("Failed to get authorization code");
        }

        // Exchange code for tokens
        exchangeCode(code);
    }

    private void startCallbackServer(CompletableFuture<String> codeFuture) {
        new Thread(() -> {
            try {
                com.sun.net.httpserver.HttpServer server = com.sun.net.httpserver.HttpServer.create(
                    new java.net.InetSocketAddress(8093), 0);
                
                server.createContext("/callback", exchange -> {
                    String query = exchange.getRequestURI().getQuery();
                    Map<String, String> params = parseQuery(query);
                    
                    String code = params.get("code");
                    String state = params.get("state");
                    
                    // Send response
                    String response = "Authorization successful! You can close this window.";
                    exchange.sendResponseHeaders(200, response.length());
                    exchange.getResponseBody().write(response.getBytes());
                    exchange.close();
                    
                    // Complete future with code
                    codeFuture.complete(code);
                    
                    // Stop server
                    server.stop(0);
                });
                
                server.start();
            } catch (IOException e) {
                codeFuture.completeExceptionally(e);
            }
        }).start();
    }

    private Map<String, String> parseQuery(String query) {
        return java.util.Arrays.stream(query.split("&"))
            .map(param -> param.split("="))
            .collect(java.util.stream.Collectors.toMap(
                param -> param[0],
                param -> param.length > 1 ? param[1] : ""
            ));
    }

    public void exchangeCode(String code) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        String body = String.format(
            "grant_type=authorization_code&code=%s&client_id=%s&client_secret=%s&redirect_uri=%s",
            code, clientId, clientSecret, redirectUri);

        HttpEntity<String> request = new HttpEntity<>(body, headers);
        ResponseEntity<Map> response = restTemplate.postForEntity(tokenUrl, request, Map.class);

        if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
            Map<String, Object> tokenResponse = response.getBody();
            accessToken = (String) tokenResponse.get("access_token");
            refreshToken = (String) tokenResponse.get("refresh_token");
            scope = (String) tokenResponse.get("scope");
        } else {
            throw new RuntimeException("Failed to exchange code for tokens");
        }
    }

    public void refreshAccessToken() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        String body = String.format(
            "grant_type=refresh_token&refresh_token=%s&client_id=%s&client_secret=%s",
            refreshToken, clientId, clientSecret);

        HttpEntity<String> request = new HttpEntity<>(body, headers);
        ResponseEntity<Map> response = restTemplate.postForEntity(tokenUrl, request, Map.class);

        if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
            Map<String, Object> tokenResponse = response.getBody();
            accessToken = (String) tokenResponse.get("access_token");
            refreshToken = (String) tokenResponse.get("refresh_token");
            scope = (String) tokenResponse.get("scope");
        } else {
            throw new RuntimeException("Failed to refresh access token");
        }
    }

    public ResponseEntity<Map> callSecureEndpoint(String url, HttpMethod method, Map<String, Object> body) {
        if (accessToken == null) {
            throw new RuntimeException("Not authenticated. Call startAuthorization() first.");
        }

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        headers.setContentType(MediaType.APPLICATION_JSON);

        HttpEntity<?> request = new HttpEntity<>(body, headers);
        return restTemplate.exchange(url, method, request, Map.class);
    }

    public static void main(String[] args) {
        try {
            OAuth2Client client = new OAuth2Client(
                "client_id",
                "client_secret_123",
                "http://localhost:8093/callback",
                "http://localhost:5013/oauth/authorize",
                "http://localhost:5013/oauth/token"
            );

            // Start authorization flow
            client.startAuthorization();

            // Test GET request
            ResponseEntity<Map> getResponse = client.callSecureEndpoint(
                "http://localhost:5013/api/secure",
                HttpMethod.GET,
                null
            );
            System.out.println("GET Response: " + getResponse.getBody());

            // Test POST request
            Map<String, Object> postBody = Map.of(
                "message", "Hello from OAuth 2.0 client!"
            );
            ResponseEntity<Map> postResponse = client.callSecureEndpoint(
                "http://localhost:5013/api/secure",
                HttpMethod.POST,
                postBody
            );
            System.out.println("POST Response: " + postResponse.getBody());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
} 