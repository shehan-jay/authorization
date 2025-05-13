package com.auth.basic;

import com.auth.base.Authentication;
import org.springframework.http.HttpStatus;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class BasicAuth implements Authentication {
    private final Map<String, String> credentials;

    public BasicAuth(String credentials) {
        this.credentials = parseCredentials(credentials);
    }

    private Map<String, String> parseCredentials(String credentials) {
        Map<String, String> result = new HashMap<>();
        String[] parts = credentials.split(":");
        if (parts.length == 2) {
            result.put("username", parts[0]);
            result.put("password", parts[1]);
        }
        return result;
    }

    @Override
    public ResponseEntity<Void> authenticate(RequestEntity<Void> request) {
        String authHeader = request.getHeaders().getFirst("Authorization");
        if (authHeader == null || !authHeader.startsWith("Basic ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        String base64Credentials = authHeader.substring(6);
        String decodedCredentials = new String(Base64.getDecoder().decode(base64Credentials));
        String[] parts = decodedCredentials.split(":", 2);

        if (parts.length != 2) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        String username = parts[0];
        String password = parts[1];

        if (!username.equals(credentials.get("username")) || 
            !password.equals(credentials.get("password"))) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        return ResponseEntity.ok().build();
    }

    @Override
    public String getType() {
        return "basic";
    }
} 