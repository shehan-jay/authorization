package com.auth.saml;

import org.springframework.http.*;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.*;
import java.util.Base64;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.StringWriter;

/**
 * SAML client for authentication.
 */
public class SAMLClient {
    private final String entityId;
    private final String acsUrl;
    private final String idpSsoUrl;
    private final RestTemplate restTemplate;
    private String assertion;

    /**
     * Initialize SAML client.
     * @param entityId Entity identifier
     * @param acsUrl Assertion Consumer Service URL
     * @param idpSsoUrl Identity Provider SSO URL
     */
    public SAMLClient(String entityId, String acsUrl, String idpSsoUrl) {
        this.entityId = entityId;
        this.acsUrl = acsUrl;
        this.idpSsoUrl = idpSsoUrl;
        this.restTemplate = new RestTemplate();
    }

    /**
     * Start SAML authentication flow.
     * @throws IOException if browser cannot be opened
     * @throws InterruptedException if authentication is interrupted
     * @throws ExecutionException if authentication fails
     */
    public void startAuthentication() throws IOException, InterruptedException, ExecutionException {
        // Generate state parameter
        String state = UUID.randomUUID().toString();

        // Generate auth request
        String authRequest = generateAuthRequest(state);

        // Start local server to receive callback
        CompletableFuture<String> callbackFuture = startCallbackServer();

        // Open browser for authentication
        String authUrl = idpSsoUrl + "?SAMLRequest=" + authRequest + "&RelayState=" + state;
        openBrowser(authUrl);

        // Wait for callback
        String samlResponse = callbackFuture.get();
        handleSamlResponse(samlResponse);
    }

    /**
     * Generate SAML authentication request.
     * @param state State parameter
     * @return Base64 encoded SAML authentication request
     */
    private String generateAuthRequest(String state) {
        try {
            // Create request XML
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.newDocument();

            Element authnRequest = doc.createElementNS("urn:oasis:names:tc:SAML:2.0:protocol", "samlp:AuthnRequest");
            authnRequest.setAttribute("ID", "_" + UUID.randomUUID().toString());
            authnRequest.setAttribute("Version", "2.0");
            authnRequest.setAttribute("IssueInstant", new Date().toInstant().toString());
            authnRequest.setAttribute("ProtocolBinding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
            authnRequest.setAttribute("AssertionConsumerServiceURL", acsUrl);
            doc.appendChild(authnRequest);

            // Add issuer
            Element issuer = doc.createElementNS("urn:oasis:names:tc:SAML:2.0:assertion", "saml:Issuer");
            issuer.setTextContent(entityId);
            authnRequest.appendChild(issuer);

            // Convert to base64
            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            Transformer transformer = transformerFactory.newTransformer();
            StringWriter writer = new StringWriter();
            transformer.transform(new DOMSource(doc), new StreamResult(writer));
            return Base64.getEncoder().encodeToString(writer.toString().getBytes());

        } catch (Exception e) {
            throw new RuntimeException("Failed to generate auth request", e);
        }
    }

    /**
     * Start local server to receive SAML callback.
     * @return Future that completes with SAML response
     */
    private CompletableFuture<String> startCallbackServer() {
        CompletableFuture<String> future = new CompletableFuture<>();

        new Thread(() -> {
            try {
                // Create HTTP server
                com.sun.net.httpserver.HttpServer server = com.sun.net.httpserver.HttpServer.create(
                    new java.net.InetSocketAddress(5015), 0);

                // Add handler for callback
                server.createContext("/", exchange -> {
                    try {
                        // Parse query parameters
                        String query = exchange.getRequestURI().getQuery();
                        Map<String, String> params = parseQueryString(query);

                        // Get SAML response
                        String samlResponse = params.get("SAMLResponse");
                        if (samlResponse != null) {
                            future.complete(samlResponse);
                            String response = "Authentication successful! You can close this window.";
                            exchange.sendResponseHeaders(200, response.length());
                            exchange.getResponseBody().write(response.getBytes());
                        } else {
                            String response = "Authentication failed!";
                            exchange.sendResponseHeaders(400, response.length());
                            exchange.getResponseBody().write(response.getBytes());
                        }
                    } catch (Exception e) {
                        future.completeExceptionally(e);
                        String response = "Error: " + e.getMessage();
                        exchange.sendResponseHeaders(500, response.length());
                        exchange.getResponseBody().write(response.getBytes());
                    } finally {
                        exchange.close();
                    }
                });

                server.start();
            } catch (Exception e) {
                future.completeExceptionally(e);
            }
        }).start();

        return future;
    }

    /**
     * Open browser for authentication.
     * @param url URL to open
     * @throws IOException if browser cannot be opened
     */
    private void openBrowser(String url) throws IOException {
        Runtime runtime = Runtime.getRuntime();
        String os = System.getProperty("os.name").toLowerCase();
        if (os.contains("win")) {
            runtime.exec("rundll32 url.dll,FileProtocolHandler " + url);
        } else if (os.contains("mac")) {
            runtime.exec("open " + url);
        } else if (os.contains("nix") || os.contains("nux")) {
            runtime.exec("xdg-open " + url);
        }
    }

    /**
     * Handle SAML response.
     * @param samlResponse SAML response to handle
     */
    private void handleSamlResponse(String samlResponse) {
        try {
            // Decode and parse response
            String responseXml = new String(Base64.getDecoder().decode(samlResponse));
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new java.io.ByteArrayInputStream(responseXml.getBytes()));

            // Store assertion
            this.assertion = samlResponse;

        } catch (Exception e) {
            throw new RuntimeException("Failed to handle SAML response", e);
        }
    }

    /**
     * Parse query string into map.
     * @param query Query string to parse
     * @return Map of parameters
     */
    private Map<String, String> parseQueryString(String query) {
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
     * Call secure endpoint with SAML authentication.
     * @param url Endpoint URL
     * @param method HTTP method
     * @param body Request body
     * @return Response entity
     */
    public ResponseEntity<Map> callSecureEndpoint(String url, String method, Map<String, Object> body) {
        if (assertion == null) {
            throw new IllegalStateException("Not authenticated. Call startAuthentication() first.");
        }

        // Create headers
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "SAML " + assertion);
        headers.setContentType(MediaType.APPLICATION_JSON);

        // Create request entity
        HttpEntity<?> requestEntity;
        if (body != null) {
            requestEntity = new HttpEntity<>(body, headers);
        } else {
            requestEntity = new HttpEntity<>(headers);
        }

        // Make request
        if ("GET".equalsIgnoreCase(method)) {
            return restTemplate.exchange(url, HttpMethod.GET, requestEntity, Map.class);
        } else if ("POST".equalsIgnoreCase(method)) {
            return restTemplate.exchange(url, HttpMethod.POST, requestEntity, Map.class);
        } else {
            throw new IllegalArgumentException("Unsupported HTTP method: " + method);
        }
    }

    /**
     * Example usage of SAML client.
     * @param args Command line arguments
     */
    public static void main(String[] args) {
        try {
            // Create client
            SAMLClient client = new SAMLClient(
                "http://localhost:5014/sp",
                "http://localhost:5015",
                "http://localhost:5014/saml/sso"
            );

            // Start authentication
            System.out.println("Starting SAML authentication...");
            client.startAuthentication();
            System.out.println("Authentication successful!");

            // Make GET request
            System.out.println("\nMaking GET request to secure endpoint...");
            ResponseEntity<Map> getResponse = client.callSecureEndpoint(
                "http://localhost:5014/api/secure",
                "GET",
                null
            );
            System.out.println("GET Response: " + getResponse.getBody());

            // Make POST request
            System.out.println("\nMaking POST request to secure endpoint...");
            Map<String, Object> postData = new HashMap<>();
            postData.put("message", "Hello from SAML client!");
            ResponseEntity<Map> postResponse = client.callSecureEndpoint(
                "http://localhost:5014/api/secure",
                "POST",
                postData
            );
            System.out.println("POST Response: " + postResponse.getBody());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
} 