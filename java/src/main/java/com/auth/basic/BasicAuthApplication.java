package com.auth.basic;

import com.auth.base.BaseAuth;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import javax.servlet.http.HttpServletRequest;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@SpringBootApplication
public class BasicAuthApplication {
    public static void main(String[] args) {
        SpringApplication.run(BasicAuthApplication.class, args);
    }

    @Configuration
    @EnableWebSecurity
    public static class SecurityConfig extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/api/secure/**").authenticated()
                .anyRequest().permitAll()
                .and()
                .addFilter(new BasicAuth());
        }
    }

    public static class BasicAuth extends BaseAuth {
        private static final Map<String, String> CREDENTIALS = new ConcurrentHashMap<>();

        public BasicAuth() {
            setPort(8081);
            // Add some test credentials
            CREDENTIALS.put("admin", "password123");
        }

        @Override
        protected boolean authenticate(HttpServletRequest request) {
            String authHeader = request.getHeader("Authorization");
            if (authHeader == null || !authHeader.startsWith("Basic ")) {
                return false;
            }

            try {
                // Decode the base64 encoded credentials
                String encodedCredentials = authHeader.substring(6);
                String decodedCredentials = new String(Base64.getDecoder().decode(encodedCredentials));
                String[] parts = decodedCredentials.split(":");
                
                if (parts.length != 2) {
                    return false;
                }

                String username = parts[0];
                String password = parts[1];

                // Check if credentials are valid
                return CREDENTIALS.containsKey(username) && CREDENTIALS.get(username).equals(password);
            } catch (Exception e) {
                return false;
            }
        }
    }

    @RestController
    @RequestMapping("/api")
    public static class SecureController {
        @GetMapping("/secure")
        public Map<String, String> secureEndpoint() {
            Map<String, String> response = new HashMap<>();
            response.put("message", "This is a secure endpoint that requires Basic Authentication");
            response.put("status", "success");
            return response;
        }
    }
} 