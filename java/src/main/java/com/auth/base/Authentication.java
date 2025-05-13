package com.auth.base;

import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;

/**
 * Interface for authentication handlers.
 */
public interface Authentication {
    /**
     * Authenticate the request.
     * @param request HTTP request to authenticate
     * @return ResponseEntity with the authentication result
     */
    ResponseEntity<Void> authenticate(RequestEntity<Void> request);

    /**
     * Get the type of authentication.
     * @return String representing the authentication type
     */
    String getType();
} 