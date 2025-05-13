package com.auth.oidc;

import org.springframework.http.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

import java.awt.Desktop;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.Base64;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

/**
 * OpenID Connect client for authentication.
 */
public class OIDCClient {
    private final String clientId;
    private final String clientSecret;
    private final String redirectUri;
    private final String issuerUrl;
    private final RestTemplate restTemplate;
    private final Map<String, Object> oidcConfig;
    private String accessToken;
    private String refreshToken;
    private String idToken;
    private Map<String, Object> userInfo;

    /**
     * Initialize OpenID Connect client.
     * @param clientId Client identifier
     * @param clientSecret Client secret
     * @param redirectUri Redirect URI
     * @param issuerUrl Issuer URL
     */
    public OIDCClient(String clientId, String clientSecret, String redirectUri, String issuerUrl) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.redirectUri = redirectUri;
        this.issuerUrl = issuerUrl;
        this.restTemplate = new RestTemplate();
        this.oidcConfig = loadOIDCConfiguration();
    }

    /**
     * Load OpenID Connect configuration from issuer.
     * @return OpenID Connect configuration
     */
    private Map<String, Object> loadOIDCConfiguration() {
        String configUrl = issuerUrl + "/.well-known/openid-configuration";
        ResponseEntity<Map> response = restTemplate.getForEntity(configUrl, Map.class);
        return response.getBody();
    }

    /**
     * Start OpenID Connect authentication flow.
     * @throws Exception if authentication fails
     */
    public void startAuthentication() throws Exception {
        // Generate state and nonce
        String state = Base64.getUrlEncoder().encodeToString(UUID.randomUUID().toString().getBytes());
        String nonce = Base64.getUrlEncoder().encodeToString(UUID.randomUUID().toString().getBytes());

        // Start local server for callback
        CompletableFuture<String> codeFuture = startCallbackServer();

        // Build authorization URL
        String authUrl = UriComponentsBuilder.fromUriString((String) oidcConfig.get("authorization_endpoint"))
            .queryParam("client_id", clientId)
            .queryParam("redirect_uri", redirectUri)
            .queryParam("response_type", "code")
            .queryParam("scope", "openid profile email")
            .queryParam("state", state)
            .queryParam("nonce", nonce)
            .build()
            .toUriString();

        // Open browser for authentication
        openBrowser(authUrl);

        // Wait for authorization code
        String code = codeFuture.get(5, TimeUnit.MINUTES);

        // Exchange code for tokens
        handleAuthorizationCode(code);
    }

    /**
     * Start local server to receive callback.
     * @return Future that completes with authorization code
     * @throws IOException if server cannot be started
     */
    private CompletableFuture<String> startCallbackServer() throws IOException {
        CompletableFuture<String> codeFuture = new CompletableFuture<>();
        HttpServer server = HttpServer.create(new java.net.InetSocketAddress(5016), 0);

        server.createContext("/callback", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                try {
                    // Parse query parameters
                    String query = exchange.getRequestURI().getQuery();
                    Map<String, String> params = parseQuery(query);

                    // Check for error
                    if (params.containsKey("error")) {
                        String error = params.get("error");
                        String errorDescription = params.get("error_description");
                        String response = "Error: " + error + "\nDescription: " + errorDescription;
                        exchange.sendResponseHeaders(400, response.length());
                        exchange.getResponseBody().write(response.getBytes());
                        codeFuture.completeExceptionally(new RuntimeException(error + ": " + errorDescription));
                        return;
                    }

                    // Validate state
                    String state = params.get("state");
                    if (state == null) {
                        String response = "Error: Missing state parameter";
                        exchange.sendResponseHeaders(400, response.length());
                        exchange.getResponseBody().write(response.getBytes());
                        codeFuture.completeExceptionally(new RuntimeException("Missing state parameter"));
                        return;
                    }

                    // Get authorization code
                    String code = params.get("code");
                    if (code == null) {
                        String response = "Error: Missing code parameter";
                        exchange.sendResponseHeaders(400, response.length());
                        exchange.getResponseBody().write(response.getBytes());
                        codeFuture.completeExceptionally(new RuntimeException("Missing code parameter"));
                        return;
                    }

                    // Send success response
                    String response = "Authentication successful! You can close this window.";
                    exchange.sendResponseHeaders(200, response.length());
                    exchange.getResponseBody().write(response.getBytes());

                    // Complete future with code
                    codeFuture.complete(code);

                } catch (Exception e) {
                    String response = "Error: " + e.getMessage();
                    exchange.sendResponseHeaders(500, response.length());
                    exchange.getResponseBody().write(response.getBytes());
                    codeFuture.completeExceptionally(e);
                }
            }
        });

        server.setExecutor(null);
        server.start();
        return codeFuture;
    }

    /**
     * Open browser for authentication.
     * @param url URL to open
     * @throws IOException if browser cannot be opened
     * @throws URISyntaxException if URL is invalid
     */
    private void openBrowser(String url) throws IOException, URISyntaxException {
        if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
            Desktop.getDesktop().browse(new URI(url));
        } else {
            throw new IOException("Desktop browsing not supported");
        }
    }

    /**
     * Parse query string into map.
     * @param query Query string to parse
     * @return Map of parameters
     */
    private Map<String, String> parseQuery(String query) {
        Map<String, String> params = new HashMap<>();
        if (query != null) {
            for (String param : query.split("&")) {
                String[] pair = param.split("=");
                if (pair.length == 2) {
                    params.put(pair[0], pair[1]);
                }
            }
        }
        return params;
    }

    /**
     * Handle authorization code.
     * @param code Authorization code
     */
    private void handleAuthorizationCode(String code) {
        // Prepare token request
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "authorization_code");
        body.add("client_id", clientId);
        body.add("client_secret", clientSecret);
        body.add("code", code);
        body.add("redirect_uri", redirectUri);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

        // Exchange code for tokens
        ResponseEntity<Map> response = restTemplate.postForEntity(
            (String) oidcConfig.get("token_endpoint"),
            request,
            Map.class
        );

        Map<String, Object> tokens = response.getBody();
        this.accessToken = (String) tokens.get("access_token");
        this.refreshToken = (String) tokens.get("refresh_token");
        this.idToken = (String) tokens.get("id_token");

        // Verify ID token
        verifyIDToken();

        // Get user info
        getUserInfo();
    }

    /**
     * Verify ID token.
     * @throws RuntimeException if token verification fails
     */
    private void verifyIDToken() {
        try {
            Claims claims = Jwts.parserBuilder()
                .setSigningKey(Keys.hmacShaKeyFor(clientSecret.getBytes()))
                .build()
                .parseClaimsJws(idToken)
                .getBody();

            // Verify claims
            if (!claims.getIssuer().equals(issuerUrl)) {
                throw new RuntimeException("Invalid issuer");
            }
            if (!claims.getAudience().equals(clientId)) {
                throw new RuntimeException("Invalid audience");
            }
            if (claims.getExpiration().before(new Date())) {
                throw new RuntimeException("Token expired");
            }

        } catch (Exception e) {
            throw new RuntimeException("Failed to verify ID token: " + e.getMessage());
        }
    }

    /**
     * Get user info.
     */
    private void getUserInfo() {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);

        HttpEntity<?> request = new HttpEntity<>(headers);

        ResponseEntity<Map> response = restTemplate.exchange(
            (String) oidcConfig.get("userinfo_endpoint"),
            HttpMethod.GET,
            request,
            Map.class
        );

        this.userInfo = response.getBody();
    }

    /**
     * Refresh access token.
     */
    public void refreshAccessToken() {
        // Prepare token request
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "refresh_token");
        body.add("client_id", clientId);
        body.add("client_secret", clientSecret);
        body.add("refresh_token", refreshToken);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

        // Exchange refresh token for new access token
        ResponseEntity<Map> response = restTemplate.postForEntity(
            (String) oidcConfig.get("token_endpoint"),
            request,
            Map.class
        );

        Map<String, Object> tokens = response.getBody();
        this.accessToken = (String) tokens.get("access_token");
        this.refreshToken = (String) tokens.get("refresh_token");
    }

    /**
     * Call secure endpoint with access token.
     * @param url Endpoint URL
     * @param method HTTP method
     * @param body Request body
     * @return Response entity
     */
    public ResponseEntity<Map> callSecureEndpoint(String url, HttpMethod method, Object body) {
        if (accessToken == null) {
            throw new IllegalStateException("Not authenticated. Call startAuthentication() first.");
        }

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        headers.setContentType(MediaType.APPLICATION_JSON);

        HttpEntity<?> request = new HttpEntity<>(body, headers);
        return restTemplate.exchange(url, method, request, Map.class);
    }

    /**
     * Example usage of OpenID Connect client.
     * @param args Command line arguments
     */
    public static void main(String[] args) {
        try {
            // Create client
            OIDCClient client = new OIDCClient(
                "client123",
                "secret123",
                "http://localhost:5016/callback",
                "http://localhost:5016"
            );

            // Start authentication
            System.out.println("Starting OpenID Connect authentication...");
            client.startAuthentication();
            System.out.println("Authentication successful!");

            // Make GET request
            System.out.println("\nMaking GET request to secure endpoint...");
            ResponseEntity<Map> getResponse = client.callSecureEndpoint(
                "http://localhost:5016/api/secure",
                HttpMethod.GET,
                null
            );
            System.out.println("GET Response: " + getResponse.getBody());

            // Make POST request
            System.out.println("\nMaking POST request to secure endpoint...");
            Map<String, Object> postData = new HashMap<>();
            postData.put("message", "Hello from OpenID Connect client!");
            ResponseEntity<Map> postResponse = client.callSecureEndpoint(
                "http://localhost:5016/api/secure",
                HttpMethod.POST,
                postData
            );
            System.out.println("POST Response: " + postResponse.getBody());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
} 