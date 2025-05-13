package com.auth.oidc;

import com.auth.base.Authentication;
import org.springframework.http.HttpStatus;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;

public class OIDCAuth implements Authentication {
    private final String issuer;
    private final String clientId;
    private final String clientSecret;
    private final String audience;

    public OIDCAuth(String issuer, String clientId, String clientSecret, String audience) {
        this.issuer = issuer;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.audience = audience;
    }

    @Override
    public ResponseEntity<Void> authenticate(RequestEntity<Void> request) {
        String authHeader = request.getHeaders().getFirst("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        String idToken = authHeader.substring(7);
        // In a real implementation, we would verify the ID token here
        // This is a simplified version that just checks if the token is present
        if (idToken == null || idToken.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        return ResponseEntity.ok().build();
    }

    @Override
    public String getType() {
        return "oidc";
    }
} 