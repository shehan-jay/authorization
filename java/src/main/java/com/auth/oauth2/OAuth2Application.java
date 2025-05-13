package com.auth.oauth2;

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

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

@SpringBootApplication
public class OAuth2Application {
    public static void main(String[] args) {
        SpringApplication.run(OAuth2Application.class, args);
    }

    @Configuration
    @EnableWebSecurity
    public static class SecurityConfig extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/oauth/**").permitAll()
                .antMatchers("/api/secure/**").authenticated()
                .anyRequest().permitAll()
                .and()
                .addFilterBefore(oauth2AuthFilter(), UsernamePasswordAuthenticationFilter.class);
        }

        @Bean
        public OAuth2AuthFilter oauth2AuthFilter() {
            return new OAuth2AuthFilter();
        }
    }

    public static class OAuth2Auth extends BaseAuth {
        private final Map<String, OAuth2Client> clients = new ConcurrentHashMap<>();
        private final Map<String, AuthorizationCode> authorizationCodes = new ConcurrentHashMap<>();
        private final Map<String, AccessToken> accessTokens = new ConcurrentHashMap<>();
        private final Map<String, RefreshToken> refreshTokens = new ConcurrentHashMap<>();
        private final byte[] jwtSecret;

        public OAuth2Auth() {
            this.jwtSecret = Keys.secretKeyFor(SignatureAlgorithm.HS256).getEncoded();
            
            // Add test client
            clients.put("client_id", new OAuth2Client(
                "client_secret_123",
                Arrays.asList("http://localhost:8093/callback"),
                Arrays.asList("authorization_code", "refresh_token")
            ));
        }

        public boolean authenticate(HttpServletRequest request) {
            String authHeader = request.getHeader("Authorization");
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return false;
            }

            try {
                // Extract token
                String token = authHeader.substring(7);

                // Verify token
                Claims claims = Jwts.parserBuilder()
                    .setSigningKey(jwtSecret)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

                // Check if token is expired
                if (claims.getExpiration().before(new Date())) {
                    return false;
                }

                // Store claims in request
                request.setAttribute("claims", claims);
                return true;

            } catch (Exception e) {
                e.printStackTrace();
                return false;
            }
        }

        public String generateAccessToken(String clientId, String userId, String scope) {
            Date now = new Date();
            Date expiration = new Date(now.getTime() + 3600 * 1000); // 1 hour

            String token = Jwts.builder()
                .setIssuer("oauth2-server")
                .setSubject(userId)
                .claim("client_id", clientId)
                .claim("scope", scope)
                .setIssuedAt(now)
                .setExpiration(expiration)
                .signWith(Keys.hmacShaKeyFor(jwtSecret), SignatureAlgorithm.HS256)
                .compact();

            accessTokens.put(token, new AccessToken(clientId, userId, scope, expiration));
            return token;
        }

        public String generateRefreshToken(String clientId, String userId, String scope) {
            String token = UUID.randomUUID().toString();
            refreshTokens.put(token, new RefreshToken(clientId, userId, scope));
            return token;
        }

        public String generateAuthorizationCode(String clientId, String userId, String scope) {
            String code = UUID.randomUUID().toString();
            Date expiration = new Date(System.currentTimeMillis() + 600 * 1000); // 10 minutes
            authorizationCodes.put(code, new AuthorizationCode(clientId, userId, scope, expiration));
            return code;
        }
    }

    public static class OAuth2Client {
        public final String clientSecret;
        public final List<String> redirectUris;
        public final List<String> grantTypes;

        public OAuth2Client(String clientSecret, List<String> redirectUris, List<String> grantTypes) {
            this.clientSecret = clientSecret;
            this.redirectUris = redirectUris;
            this.grantTypes = grantTypes;
        }
    }

    public static class AuthorizationCode {
        public final String clientId;
        public final String userId;
        public final String scope;
        public final Date expiresAt;

        public AuthorizationCode(String clientId, String userId, String scope, Date expiresAt) {
            this.clientId = clientId;
            this.userId = userId;
            this.scope = scope;
            this.expiresAt = expiresAt;
        }
    }

    public static class AccessToken {
        public final String clientId;
        public final String userId;
        public final String scope;
        public final Date expiresAt;

        public AccessToken(String clientId, String userId, String scope, Date expiresAt) {
            this.clientId = clientId;
            this.userId = userId;
            this.scope = scope;
            this.expiresAt = expiresAt;
        }
    }

    public static class RefreshToken {
        public final String clientId;
        public final String userId;
        public final String scope;

        public RefreshToken(String clientId, String userId, String scope) {
            this.clientId = clientId;
            this.userId = userId;
            this.scope = scope;
        }
    }

    public static class OAuth2AuthFilter extends OncePerRequestFilter {
        private final OAuth2Auth auth = new OAuth2Auth();

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws ServletException, IOException {
            if (!auth.authenticate(request)) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("Invalid OAuth 2.0 authentication");
                return;
            }
            chain.doFilter(request, response);
        }
    }

    @RestController
    @RequestMapping("/oauth")
    public static class OAuth2Controller {
        private final OAuth2Auth auth = new OAuth2Auth();

        @GetMapping("/authorize")
        public ResponseEntity<?> authorize(
                @RequestParam String client_id,
                @RequestParam String redirect_uri,
                @RequestParam String response_type,
                @RequestParam(required = false) String scope,
                @RequestParam(required = false) String state) {
            
            // Validate client
            if (!auth.clients.containsKey(client_id)) {
                return ResponseEntity.badRequest().body(Map.of("error", "invalid_client"));
            }

            // Validate redirect URI
            if (!auth.clients.get(client_id).redirectUris.contains(redirect_uri)) {
                return ResponseEntity.badRequest().body(Map.of("error", "invalid_redirect_uri"));
            }

            // For demonstration, we'll auto-approve the request
            if ("code".equals(response_type)) {
                String code = auth.generateAuthorizationCode(client_id, "user123", scope);
                return ResponseEntity.status(HttpServletResponse.SC_FOUND)
                    .header("Location", redirect_uri + "?code=" + code + "&state=" + state)
                    .build();
            } else {
                return ResponseEntity.badRequest().body(Map.of("error", "unsupported_response_type"));
            }
        }

        @PostMapping("/token")
        public ResponseEntity<?> token(@RequestParam Map<String, String> params) {
            String grantType = params.get("grant_type");
            String clientId = params.get("client_id");
            String clientSecret = params.get("client_secret");

            // Validate client credentials
            if (!auth.clients.containsKey(clientId) || 
                !auth.clients.get(clientId).clientSecret.equals(clientSecret)) {
                return ResponseEntity.status(HttpServletResponse.SC_UNAUTHORIZED)
                    .body(Map.of("error", "invalid_client"));
            }

            if ("authorization_code".equals(grantType)) {
                String code = params.get("code");
                if (!auth.authorizationCodes.containsKey(code)) {
                    return ResponseEntity.badRequest().body(Map.of("error", "invalid_grant"));
                }

                AuthorizationCode authCode = auth.authorizationCodes.get(code);
                if (authCode.expiresAt.before(new Date())) {
                    return ResponseEntity.badRequest().body(Map.of("error", "invalid_grant"));
                }

                // Generate tokens
                String accessToken = auth.generateAccessToken(
                    authCode.clientId, authCode.userId, authCode.scope);
                String refreshToken = auth.generateRefreshToken(
                    authCode.clientId, authCode.userId, authCode.scope);

                // Remove used authorization code
                auth.authorizationCodes.remove(code);

                return ResponseEntity.ok(Map.of(
                    "access_token", accessToken,
                    "token_type", "Bearer",
                    "expires_in", 3600,
                    "refresh_token", refreshToken,
                    "scope", authCode.scope
                ));

            } else if ("refresh_token".equals(grantType)) {
                String refreshToken = params.get("refresh_token");
                if (!auth.refreshTokens.containsKey(refreshToken)) {
                    return ResponseEntity.badRequest().body(Map.of("error", "invalid_grant"));
                }

                RefreshToken token = auth.refreshTokens.get(refreshToken);
                String accessToken = auth.generateAccessToken(
                    token.clientId, token.userId, token.scope);

                return ResponseEntity.ok(Map.of(
                    "access_token", accessToken,
                    "token_type", "Bearer",
                    "expires_in", 3600,
                    "scope", token.scope
                ));

            } else {
                return ResponseEntity.badRequest().body(Map.of("error", "unsupported_grant_type"));
            }
        }
    }

    @RestController
    @RequestMapping("/api")
    public static class SecureController {
        @GetMapping("/secure")
        public ResponseEntity<Map<String, Object>> secureGet(HttpServletRequest request) {
            Claims claims = (Claims) request.getAttribute("claims");
            Map<String, Object> response = new HashMap<>();
            response.put("message", "This is a secure endpoint that requires OAuth 2.0 authentication");
            response.put("status", "success");
            response.put("claims", claims);

            return ResponseEntity.ok(response);
        }

        @PostMapping("/secure")
        public ResponseEntity<Map<String, Object>> securePost(
                HttpServletRequest request,
                @RequestBody(required = false) Map<String, Object> body) {
            Claims claims = (Claims) request.getAttribute("claims");
            Map<String, Object> response = new HashMap<>();
            response.put("message", "This is a secure endpoint that requires OAuth 2.0 authentication");
            response.put("status", "success");
            response.put("claims", claims);
            response.put("received_data", body);

            return ResponseEntity.ok(response);
        }
    }
} 