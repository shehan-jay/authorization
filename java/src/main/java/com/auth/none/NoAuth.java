package com.auth.none;

import com.auth.base.Authentication;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;

public class NoAuth implements Authentication {
    public NoAuth() {
        // No configuration needed
    }

    @Override
    public ResponseEntity<Void> authenticate(RequestEntity<Void> request) {
        // Always return OK as no authentication is required
        return ResponseEntity.ok().build();
    }

    @Override
    public String getType() {
        return "none";
    }
} 