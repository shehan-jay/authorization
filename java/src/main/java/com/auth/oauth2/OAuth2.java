package com.auth.oauth2;

import com.auth.base.Authentication;
import org.springframework.http.HttpStatus;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;

public class OAuth2 implements Authentication {
    private final String clientId;
    private final String clientSecret;

    public OAuth2(String clientId, String clientSecret) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    @Override
    public ResponseEntity<Void> authenticate(RequestEntity<Void> request) {
        String authHeader = request.getHeaders().getFirst("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        String accessToken = authHeader.substring(7);
        // In a real implementation, we would validate the access token against an OAuth 2.0 provider
        // This is a simplified version that just checks if the token is present
        if (accessToken == null || accessToken.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        return ResponseEntity.ok().build();
    }

    @Override
    public String getType() {
        return "oauth2";
    }
} 