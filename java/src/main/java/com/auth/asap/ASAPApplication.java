package com.auth.asap;

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
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

@SpringBootApplication
public class ASAPApplication {
    public static void main(String[] args) {
        SpringApplication.run(ASAPApplication.class, args);
    }

    @Configuration
    @EnableWebSecurity
    public static class SecurityConfig extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/api/token").permitAll()
                .antMatchers("/api/secure/**").authenticated()
                .anyRequest().permitAll()
                .and()
                .addFilterBefore(asapAuthFilter(), UsernamePasswordAuthenticationFilter.class);
        }

        @Bean
        public ASAPAuthFilter asapAuthFilter() {
            return new ASAPAuthFilter();
        }
    }

    public static class ASAPAuth extends BaseAuth {
        private final Map<String, ASAPCredentials> credentials = new ConcurrentHashMap<>();
        private PrivateKey privateKey;

        public ASAPAuth() {
            try {
                // Generate key pair
                KeyPair keyPair = generateKeyPair();
                privateKey = keyPair.getPrivate();
                PublicKey publicKey = keyPair.getPublic();

                // Add test credentials
                credentials.put("service.example.com", new ASAPCredentials(
                    publicKey,
                    "api.example.com"
                ));
            } catch (Exception e) {
                throw new RuntimeException("Failed to initialize ASAP auth", e);
            }
        }

        private KeyPair generateKeyPair() throws NoSuchAlgorithmException {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        }

        public boolean authenticate(HttpServletRequest request) {
            String authHeader = request.getHeader("Authorization");
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return false;
            }

            try {
                // Extract token
                String token = authHeader.substring(7);

                // Get issuer from token
                Claims unverifiedClaims = Jwts.parserBuilder()
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
                String issuer = unverifiedClaims.getIssuer();

                if (!credentials.containsKey(issuer)) {
                    return false;
                }

                // Verify token
                ASAPCredentials creds = credentials.get(issuer);
                Claims claims = Jwts.parserBuilder()
                    .setSigningKey(creds.publicKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

                // Verify audience
                if (!claims.getAudience().equals(creds.audience)) {
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

        public String generateToken(String issuer, String audience, String subject, long expiresIn) {
            if (!credentials.containsKey(issuer)) {
                throw new IllegalArgumentException("Unknown issuer");
            }

            Date now = new Date();
            Date expiration = new Date(now.getTime() + expiresIn * 1000);

            return Jwts.builder()
                .setIssuer(issuer)
                .setSubject(subject)
                .setAudience(audience)
                .setIssuedAt(now)
                .setExpiration(expiration)
                .setId(now.getTime() + "-" + subject)
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();
        }
    }

    public static class ASAPCredentials {
        public final PublicKey publicKey;
        public final String audience;

        public ASAPCredentials(PublicKey publicKey, String audience) {
            this.publicKey = publicKey;
            this.audience = audience;
        }
    }

    public static class ASAPAuthFilter extends OncePerRequestFilter {
        private final ASAPAuth auth = new ASAPAuth();

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws ServletException, IOException {
            if (!auth.authenticate(request)) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("Invalid ASAP authentication");
                return;
            }
            chain.doFilter(request, response);
        }
    }

    @RestController
    @RequestMapping("/api")
    public static class SecureController {
        private final ASAPAuth auth = new ASAPAuth();

        @PostMapping("/token")
        public ResponseEntity<Map<String, String>> generateToken(@RequestBody Map<String, String> request) {
            try {
                String issuer = request.get("issuer");
                String audience = request.get("audience");
                String subject = request.get("subject");
                long expiresIn = Long.parseLong(request.getOrDefault("expires_in", "3600"));

                if (issuer == null || audience == null || subject == null) {
                    return ResponseEntity.badRequest().body(Map.of("error", "Missing required fields"));
                }

                String token = auth.generateToken(issuer, audience, subject, expiresIn);
                return ResponseEntity.ok(Map.of("token", token));

            } catch (Exception e) {
                return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
            }
        }

        @GetMapping("/secure")
        public ResponseEntity<Map<String, Object>> secureGet(HttpServletRequest request) {
            Claims claims = (Claims) request.getAttribute("claims");
            Map<String, Object> response = new HashMap<>();
            response.put("message", "This is a secure endpoint that requires ASAP authentication");
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
            response.put("message", "This is a secure endpoint that requires ASAP authentication");
            response.put("status", "success");
            response.put("claims", claims);
            response.put("received_data", body);

            return ResponseEntity.ok(response);
        }
    }
} 