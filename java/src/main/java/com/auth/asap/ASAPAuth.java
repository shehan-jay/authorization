package com.auth.asap;

import com.auth.base.Authentication;
import org.springframework.http.HttpStatus;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ASAPAuth implements Authentication {
    private final String issuer;
    private final String audience;
    private final String privateKey;

    public ASAPAuth(String issuer, String audience, String privateKey) {
        this.issuer = issuer;
        this.audience = audience;
        this.privateKey = privateKey;
    }

    @Override
    public ResponseEntity<Void> authenticate(RequestEntity<Void> request) {
        String authHeader = request.getHeaders().getFirst("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        String token = authHeader.substring(7);
        // In a real implementation, we would verify the JWT token here
        // This is a simplified version that just checks if the token is present
        if (token == null || token.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        return ResponseEntity.ok().build();
    }

    @Override
    public String getType() {
        return "asap";
    }
} 