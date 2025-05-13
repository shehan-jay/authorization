package com.auth.oidc;

import com.auth.base.BaseAuth;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.ResponseEntity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Base64;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.io.ByteArrayInputStream;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

/**
 * Spring Boot application implementing OpenID Connect authentication.
 */
@SpringBootApplication
public class OIDCApplication {
    public static void main(String[] args) {
        SpringApplication.run(OIDCApplication.class, args);
    }

    /**
     * Security configuration for OpenID Connect authentication.
     */
    @Configuration
    @EnableWebSecurity
    public static class SecurityConfig extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/.well-known/**", "/authorize", "/token").permitAll()
                .antMatchers("/api/secure/**").authenticated()
                .anyRequest().permitAll()
                .and()
                .addFilterBefore(oidcAuthFilter(), UsernamePasswordAuthenticationFilter.class);
        }

        @Bean
        public OIDCAuthFilter oidcAuthFilter() {
            return new OIDCAuthFilter();
        }
    }

    /**
     * OpenID Connect authentication implementation.
     */
    public static class OIDCAuth extends BaseAuth {
        private final Map<String, OIDCClient> clients = new ConcurrentHashMap<>();
        private final Map<String, AuthorizationCode> authorizationCodes = new ConcurrentHashMap<>();
        private final Map<String, AccessToken> accessTokens = new ConcurrentHashMap<>();
        private final Map<String, RefreshToken> refreshTokens = new ConcurrentHashMap<>();
        private final Map<String, IDToken> idTokens = new ConcurrentHashMap<>();
        private final Map<String, User> users = new ConcurrentHashMap<>();
        private final KeyPair keyPair;

        /**
         * Initialize OpenID Connect authentication with key pair.
         * @throws Exception if key pair generation fails
         */
        public OIDCAuth() throws Exception {
            // Generate key pair for signing
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            this.keyPair = generator.generateKeyPair();

            // Initialize test data
            initializeTestData();
        }

        /**
         * Initialize test data for demonstration.
         */
        private void initializeTestData() {
            // Add test client
            clients.put("client123", new OIDCClient(
                "client123",
                "secret123",
                Arrays.asList("http://localhost:5016/callback"),
                Arrays.asList("authorization_code", "refresh_token")
            ));

            // Add test user
            users.put("user123", new User(
                "user123",
                "password123",
                "Test User",
                "test@example.com"
            ));
        }

        /**
         * Authenticate a request using OpenID Connect token.
         * @param request HTTP request to authenticate
         * @return true if authentication succeeds, false otherwise
         */
        @Override
        public boolean authenticate(HttpServletRequest request) {
            String authHeader = request.getHeader("Authorization");
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return false;
            }

            try {
                // Extract token
                String token = authHeader.substring(7);
                
                // Verify token
                if (!accessTokens.containsKey(token)) {
                    return false;
                }
                
                // Check expiration
                AccessToken accessToken = accessTokens.get(token);
                if (accessToken.expiresAt.before(new Date())) {
                    return false;
                }
                
                // Store token info in request
                request.setAttribute("token_info", accessToken);
                return true;

            } catch (Exception e) {
                e.printStackTrace();
                return false;
            }
        }

        /**
         * Generate an ID token.
         * @param clientId Client identifier
         * @param subject Subject identifier
         * @param nonce Nonce value
         * @return Signed ID token
         */
        public String generateIDToken(String clientId, String subject, String nonce) {
            String tokenId = "_" + UUID.randomUUID().toString();
            Date now = new Date();
            Date expiresAt = new Date(now.getTime() + 3600 * 1000); // 1 hour

            // Create token claims
            Map<String, Object> claims = new HashMap<>();
            claims.put("iss", "http://localhost:5016");
            claims.put("sub", subject);
            claims.put("aud", clientId);
            claims.put("iat", now.getTime() / 1000);
            claims.put("exp", expiresAt.getTime() / 1000);
            claims.put("jti", tokenId);
            if (nonce != null) {
                claims.put("nonce", nonce);
            }

            // Add user info
            User user = users.get(subject);
            if (user != null) {
                claims.put("name", user.name);
                claims.put("email", user.email);
            }

            // Store token
            idTokens.put(tokenId, new IDToken(clientId, subject, nonce, expiresAt));

            // Sign token
            return Jwts.builder()
                .setClaims(claims)
                .signWith(keyPair.getPrivate(), SignatureAlgorithm.RS256)
                .compact();
        }

        /**
         * Generate an access token.
         * @param clientId Client identifier
         * @param subject Subject identifier
         * @param scope Token scope
         * @return Signed access token
         */
        public String generateAccessToken(String clientId, String subject, String scope) {
            String tokenId = "_" + UUID.randomUUID().toString();
            Date now = new Date();
            Date expiresAt = new Date(now.getTime() + 3600 * 1000); // 1 hour

            // Create token claims
            Map<String, Object> claims = new HashMap<>();
            claims.put("iss", "http://localhost:5016");
            claims.put("sub", subject);
            claims.put("aud", clientId);
            claims.put("iat", now.getTime() / 1000);
            claims.put("exp", expiresAt.getTime() / 1000);
            claims.put("jti", tokenId);
            claims.put("scope", scope);

            // Store token
            accessTokens.put(tokenId, new AccessToken(clientId, subject, scope, expiresAt));

            // Sign token
            return Jwts.builder()
                .setClaims(claims)
                .signWith(keyPair.getPrivate(), SignatureAlgorithm.RS256)
                .compact();
        }

        /**
         * Generate a refresh token.
         * @param clientId Client identifier
         * @param subject Subject identifier
         * @param scope Token scope
         * @return Signed refresh token
         */
        public String generateRefreshToken(String clientId, String subject, String scope) {
            String tokenId = "_" + UUID.randomUUID().toString();

            // Store token
            refreshTokens.put(tokenId, new RefreshToken(clientId, subject, scope));

            // Sign token
            return Jwts.builder()
                .setClaims(Map.of(
                    "iss", "http://localhost:5016",
                    "sub", subject,
                    "aud", clientId,
                    "jti", tokenId,
                    "scope", scope
                ))
                .signWith(keyPair.getPrivate(), SignatureAlgorithm.RS256)
                .compact();
        }

        /**
         * Generate an authorization code.
         * @param clientId Client identifier
         * @param subject Subject identifier
         * @param scope Token scope
         * @param nonce Nonce value
         * @return Authorization code
         */
        public String generateAuthorizationCode(String clientId, String subject, String scope, String nonce) {
            String code = Base64.getUrlEncoder().encodeToString(UUID.randomUUID().toString().getBytes());
            authorizationCodes.put(code, new AuthorizationCode(clientId, subject, scope, nonce));
            return code;
        }
    }

    /**
     * OpenID Connect client data.
     */
    public static class OIDCClient {
        public final String clientId;
        public final String clientSecret;
        public final List<String> redirectUris;
        public final List<String> grantTypes;

        /**
         * Create a new OpenID Connect client.
         * @param clientId Client identifier
         * @param clientSecret Client secret
         * @param redirectUris List of redirect URIs
         * @param grantTypes List of grant types
         */
        public OIDCClient(String clientId, String clientSecret, List<String> redirectUris, List<String> grantTypes) {
            this.clientId = clientId;
            this.clientSecret = clientSecret;
            this.redirectUris = redirectUris;
            this.grantTypes = grantTypes;
        }
    }

    /**
     * User data.
     */
    public static class User {
        public final String id;
        public final String password;
        public final String name;
        public final String email;

        /**
         * Create a new user.
         * @param id User identifier
         * @param password User password
         * @param name User name
         * @param email User email
         */
        public User(String id, String password, String name, String email) {
            this.id = id;
            this.password = password;
            this.name = name;
            this.email = email;
        }
    }

    /**
     * Authorization code data.
     */
    public static class AuthorizationCode {
        public final String clientId;
        public final String subject;
        public final String scope;
        public final String nonce;

        /**
         * Create a new authorization code.
         * @param clientId Client identifier
         * @param subject Subject identifier
         * @param scope Token scope
         * @param nonce Nonce value
         */
        public AuthorizationCode(String clientId, String subject, String scope, String nonce) {
            this.clientId = clientId;
            this.subject = subject;
            this.scope = scope;
            this.nonce = nonce;
        }
    }

    /**
     * Access token data.
     */
    public static class AccessToken {
        public final String clientId;
        public final String subject;
        public final String scope;
        public final Date expiresAt;

        /**
         * Create a new access token.
         * @param clientId Client identifier
         * @param subject Subject identifier
         * @param scope Token scope
         * @param expiresAt Expiration time
         */
        public AccessToken(String clientId, String subject, String scope, Date expiresAt) {
            this.clientId = clientId;
            this.subject = subject;
            this.scope = scope;
            this.expiresAt = expiresAt;
        }
    }

    /**
     * Refresh token data.
     */
    public static class RefreshToken {
        public final String clientId;
        public final String subject;
        public final String scope;

        /**
         * Create a new refresh token.
         * @param clientId Client identifier
         * @param subject Subject identifier
         * @param scope Token scope
         */
        public RefreshToken(String clientId, String subject, String scope) {
            this.clientId = clientId;
            this.subject = subject;
            this.scope = scope;
        }
    }

    /**
     * ID token data.
     */
    public static class IDToken {
        public final String clientId;
        public final String subject;
        public final String nonce;
        public final Date expiresAt;

        /**
         * Create a new ID token.
         * @param clientId Client identifier
         * @param subject Subject identifier
         * @param nonce Nonce value
         * @param expiresAt Expiration time
         */
        public IDToken(String clientId, String subject, String nonce, Date expiresAt) {
            this.clientId = clientId;
            this.subject = subject;
            this.nonce = nonce;
            this.expiresAt = expiresAt;
        }
    }

    /**
     * OpenID Connect authentication filter.
     */
    public static class OIDCAuthFilter extends OncePerRequestFilter {
        private final OIDCAuth auth;

        /**
         * Initialize OpenID Connect authentication filter.
         */
        public OIDCAuthFilter() {
            try {
                this.auth = new OIDCAuth();
            } catch (Exception e) {
                throw new RuntimeException("Failed to initialize OIDC auth", e);
            }
        }

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws ServletException, IOException {
            if (!auth.authenticate(request)) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("Invalid OpenID Connect authentication");
                return;
            }
            chain.doFilter(request, response);
        }
    }

    /**
     * OpenID Connect controller for handling OIDC endpoints.
     */
    @RestController
    public static class OIDCController {
        private final OIDCAuth auth;

        /**
         * Initialize OpenID Connect controller.
         */
        public OIDCController() {
            try {
                this.auth = new OIDCAuth();
            } catch (Exception e) {
                throw new RuntimeException("Failed to initialize OIDC auth", e);
            }
        }

        /**
         * Get OpenID Connect configuration.
         * @return OpenID Connect configuration
         */
        @GetMapping("/.well-known/openid-configuration")
        public ResponseEntity<Map<String, Object>> openidConfiguration() {
            Map<String, Object> config = new HashMap<>();
            config.put("issuer", "http://localhost:5016");
            config.put("authorization_endpoint", "http://localhost:5016/authorize");
            config.put("token_endpoint", "http://localhost:5016/token");
            config.put("userinfo_endpoint", "http://localhost:5016/userinfo");
            config.put("jwks_uri", "http://localhost:5016/jwks");
            config.put("response_types_supported", Arrays.asList("code"));
            config.put("subject_types_supported", Arrays.asList("public"));
            config.put("id_token_signing_alg_values_supported", Arrays.asList("RS256"));
            config.put("scopes_supported", Arrays.asList("openid", "profile", "email"));
            config.put("token_endpoint_auth_methods_supported", Arrays.asList("client_secret_post"));
            config.put("claims_supported", Arrays.asList("sub", "iss", "name", "email"));
            return ResponseEntity.ok(config);
        }

        /**
         * Handle authorization request.
         * @param client_id Client identifier
         * @param redirect_uri Redirect URI
         * @param response_type Response type
         * @param scope Token scope
         * @param state State parameter
         * @param nonce Nonce value
         * @return Authorization response
         */
        @GetMapping("/authorize")
        public ResponseEntity<?> authorize(
                @RequestParam String client_id,
                @RequestParam String redirect_uri,
                @RequestParam String response_type,
                @RequestParam(required = false) String scope,
                @RequestParam(required = false) String state,
                @RequestParam(required = false) String nonce) {
            try {
                // Validate client
                if (!auth.clients.containsKey(client_id)) {
                    return ResponseEntity.badRequest().body(Map.of("error", "invalid_client"));
                }

                // Validate redirect URI
                OIDCClient client = auth.clients.get(client_id);
                if (!client.redirectUris.contains(redirect_uri)) {
                    return ResponseEntity.badRequest().body(Map.of("error", "invalid_redirect_uri"));
                }

                // For demonstration, we'll auto-authenticate the user
                String code = auth.generateAuthorizationCode(client_id, "user123", scope, nonce);

                // Redirect to callback URL
                String redirectUrl = redirect_uri + "?code=" + code;
                if (state != null) {
                    redirectUrl += "&state=" + state;
                }
                return ResponseEntity.status(HttpServletResponse.SC_FOUND)
                    .header("Location", redirectUrl)
                    .build();

            } catch (Exception e) {
                return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
            }
        }

        /**
         * Handle token request.
         * @param grant_type Grant type
         * @param client_id Client identifier
         * @param client_secret Client secret
         * @param code Authorization code
         * @param refresh_token Refresh token
         * @return Token response
         */
        @PostMapping("/token")
        public ResponseEntity<?> token(
                @RequestParam String grant_type,
                @RequestParam String client_id,
                @RequestParam String client_secret,
                @RequestParam(required = false) String code,
                @RequestParam(required = false) String refresh_token) {
            try {
                // Validate client
                if (!auth.clients.containsKey(client_id)) {
                    return ResponseEntity.badRequest().body(Map.of("error", "invalid_client"));
                }

                // Validate client secret
                OIDCClient client = auth.clients.get(client_id);
                if (!client.clientSecret.equals(client_secret)) {
                    return ResponseEntity.badRequest().body(Map.of("error", "invalid_client"));
                }

                Map<String, Object> response = new HashMap<>();

                if ("authorization_code".equals(grant_type)) {
                    // Validate code
                    if (!auth.authorizationCodes.containsKey(code)) {
                        return ResponseEntity.badRequest().body(Map.of("error", "invalid_grant"));
                    }

                    // Get code details
                    AuthorizationCode authCode = auth.authorizationCodes.get(code);
                    if (!authCode.clientId.equals(client_id)) {
                        return ResponseEntity.badRequest().body(Map.of("error", "invalid_grant"));
                    }

                    // Generate tokens
                    String accessToken = auth.generateAccessToken(client_id, authCode.subject, authCode.scope);
                    String idToken = auth.generateIDToken(client_id, authCode.subject, authCode.nonce);
                    String refreshToken = auth.generateRefreshToken(client_id, authCode.subject, authCode.scope);

                    // Build response
                    response.put("access_token", accessToken);
                    response.put("id_token", idToken);
                    response.put("refresh_token", refreshToken);
                    response.put("token_type", "Bearer");
                    response.put("expires_in", 3600);

                } else if ("refresh_token".equals(grant_type)) {
                    // Validate refresh token
                    if (!auth.refreshTokens.containsKey(refresh_token)) {
                        return ResponseEntity.badRequest().body(Map.of("error", "invalid_grant"));
                    }

                    // Get token details
                    RefreshToken token = auth.refreshTokens.get(refresh_token);
                    if (!token.clientId.equals(client_id)) {
                        return ResponseEntity.badRequest().body(Map.of("error", "invalid_grant"));
                    }

                    // Generate new access token
                    String accessToken = auth.generateAccessToken(client_id, token.subject, token.scope);

                    // Build response
                    response.put("access_token", accessToken);
                    response.put("token_type", "Bearer");
                    response.put("expires_in", 3600);

                } else {
                    return ResponseEntity.badRequest().body(Map.of("error", "unsupported_grant_type"));
                }

                return ResponseEntity.ok(response);

            } catch (Exception e) {
                return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
            }
        }

        /**
         * Get user info.
         * @param request HTTP request
         * @return User info response
         */
        @GetMapping("/userinfo")
        public ResponseEntity<?> userinfo(HttpServletRequest request) {
            try {
                AccessToken token = (AccessToken) request.getAttribute("token_info");
                if (token == null) {
                    return ResponseEntity.badRequest().body(Map.of("error", "invalid_token"));
                }

                User user = auth.users.get(token.subject);
                if (user == null) {
                    return ResponseEntity.badRequest().body(Map.of("error", "user_not_found"));
                }

                Map<String, Object> response = new HashMap<>();
                response.put("sub", user.id);
                response.put("name", user.name);
                response.put("email", user.email);

                return ResponseEntity.ok(response);

            } catch (Exception e) {
                return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
            }
        }

        /**
         * Get JSON Web Key Set.
         * @return JWKS response
         */
        @GetMapping("/jwks")
        public ResponseEntity<?> jwks() {
            Map<String, Object> response = new HashMap<>();
            response.put("keys", Arrays.asList(Map.of(
                "kty", "RSA",
                "use", "sig",
                "kid", "1",
                "x5c", Arrays.asList(Base64.getEncoder().encodeToString(auth.keyPair.getPublic().getEncoded()))
            )));
            return ResponseEntity.ok(response);
        }
    }

    /**
     * Secure controller for protected endpoints.
     */
    @RestController
    @RequestMapping("/api")
    public static class SecureController {
        /**
         * Handle secure GET request.
         * @param request HTTP request
         * @return Response data
         */
        @GetMapping("/secure")
        public ResponseEntity<Map<String, Object>> secureGet(HttpServletRequest request) {
            AccessToken token = (AccessToken) request.getAttribute("token_info");
            Map<String, Object> response = new HashMap<>();
            response.put("message", "This is a secure endpoint that requires OpenID Connect authentication");
            response.put("status", "success");
            response.put("token_info", token);

            return ResponseEntity.ok(response);
        }

        /**
         * Handle secure POST request.
         * @param request HTTP request
         * @param body Request body
         * @return Response data
         */
        @PostMapping("/secure")
        public ResponseEntity<Map<String, Object>> securePost(
                HttpServletRequest request,
                @RequestBody(required = false) Map<String, Object> body) {
            AccessToken token = (AccessToken) request.getAttribute("token_info");
            Map<String, Object> response = new HashMap<>();
            response.put("message", "This is a secure endpoint that requires OpenID Connect authentication");
            response.put("status", "success");
            response.put("token_info", token);
            response.put("received_data", body);

            return ResponseEntity.ok(response);
        }
    }
} 