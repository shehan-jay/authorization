package com.auth.bearer;

import com.auth.base.BaseAuth;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import javax.servlet.http.HttpServletRequest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@SpringBootApplication
public class BearerAuthApplication {
    public static void main(String[] args) {
        SpringApplication.run(BearerAuthApplication.class, args);
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
                .addFilter(new BearerAuth());
        }
    }

    public static class BearerAuth extends BaseAuth {
        private static final Map<String, TokenInfo> TOKENS = new ConcurrentHashMap<>();
        private static final SecureRandom secureRandom = new SecureRandom();

        public BearerAuth() {
            setPort(8082);
            // Add a test user
            generateToken("admin");
        }

        private String generateToken(String username) {
            byte[] randomBytes = new byte[32];
            secureRandom.nextBytes(randomBytes);
            String token = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
            
            TOKENS.put(username, new TokenInfo(token, System.currentTimeMillis() + 3600000)); // 1 hour expiration
            return token;
        }

        @Override
        protected boolean authenticate(HttpServletRequest request) {
            String authHeader = request.getHeader("Authorization");
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return false;
            }

            try {
                String token = authHeader.substring(7);
                for (TokenInfo tokenInfo : TOKENS.values()) {
                    if (tokenInfo.token.equals(token) && tokenInfo.expiresAt > System.currentTimeMillis()) {
                        return true;
                    }
                }
                return false;
            } catch (Exception e) {
                return false;
            }
        }

        private static class TokenInfo {
            final String token;
            final long expiresAt;

            TokenInfo(String token, long expiresAt) {
                this.token = token;
                this.expiresAt = expiresAt;
            }
        }
    }

    @RestController
    @RequestMapping("/api")
    public static class AuthController {
        @PostMapping("/token")
        public Map<String, Object> getToken(@RequestBody Map<String, String> request) {
            Map<String, Object> response = new HashMap<>();
            String username = request.get("username");

            if (username == null) {
                response.put("message", "Username is required");
                response.put("status", "error");
                return response;
            }

            BearerAuth auth = new BearerAuth();
            String token = auth.generateToken(username);
            if (token == null) {
                response.put("message", "Invalid username");
                response.put("status", "error");
                return response;
            }

            response.put("token", token);
            response.put("expires_in", 3600);
            response.put("status", "success");
            return response;
        }

        @GetMapping("/secure")
        public Map<String, String> secureEndpoint() {
            Map<String, String> response = new HashMap<>();
            response.put("message", "This is a secure endpoint that requires Bearer Token authentication");
            response.put("status", "success");
            return response;
        }
    }
} 