package com.auth.ntlm;

import com.auth.base.Authentication;
import org.springframework.http.HttpStatus;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;

public class NTLMAuth implements Authentication {
    private final String domain;
    private final String username;
    private final String password;

    public NTLMAuth(String domain, String username, String password) {
        this.domain = domain;
        this.username = username;
        this.password = password;
    }

    @Override
    public ResponseEntity<Void> authenticate(RequestEntity<Void> request) {
        String authHeader = request.getHeaders().getFirst("Authorization");
        if (authHeader == null || !authHeader.startsWith("NTLM ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        String token = authHeader.substring(5).trim();
        if (token.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        // In a real implementation, this would:
        // 1. Decode the NTLM token
        // 2. Extract domain, username, and challenge
        // 3. Verify the credentials against the domain controller
        // 4. Check if the user has access to the requested resource

        // For this example, we'll just check if the token is valid
        if (token.equals("TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==")) {
            return ResponseEntity.ok().build();
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }

    @Override
    public String getType() {
        return "ntlm";
    }
} 