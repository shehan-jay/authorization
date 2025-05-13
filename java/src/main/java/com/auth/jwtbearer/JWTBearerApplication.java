package com.auth.jwtbearer;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
public class JWTBearerApplication {
    private static final SecretKey SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS256);
    private static final long EXPIRATION_TIME = 86400000; // 24 hours

    public static void main(String[] args) {
        SpringApplication.run(JWTBearerApplication.class, args);
    }

    @Configuration
    @EnableWebSecurity
    public static class SecurityConfig extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                .antMatchers("/api/token").permitAll()
                .antMatchers("/api/secure/**").authenticated()
                .anyRequest().permitAll()
                .and()
                .addFilterBefore(new JWTBearerFilter(SECRET_KEY), UsernamePasswordAuthenticationFilter.class);
        }
    }

    @RestController
    public static class TokenController {

        @PostMapping("/api/token")
        public Map<String, String> getToken() {
            String userId = "user123"; // In real app, this would be the authenticated user's ID
            String token = generateToken(userId);

            Map<String, String> response = new HashMap<>();
            response.put("access_token", token);
            response.put("token_type", "Bearer");
            response.put("expires_in", String.valueOf(EXPIRATION_TIME / 1000));
            return response;
        }

        private String generateToken(String userId) {
            return Jwts.builder()
                .setSubject(userId)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(SECRET_KEY)
                .compact();
        }
    }

    public static SecretKey getSecretKey() {
        return SECRET_KEY;
    }
} 