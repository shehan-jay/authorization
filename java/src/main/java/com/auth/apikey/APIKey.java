package com.auth.apikey;

import com.auth.base.Authentication;
import org.springframework.http.HttpStatus;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;

import java.net.URI;

public class APIKey implements Authentication {
    private final String validApiKey;

    public APIKey(String validApiKey) {
        this.validApiKey = validApiKey;
    }

    @Override
    public ResponseEntity<Void> authenticate(RequestEntity<Void> request) {
        // Check header first
        String apiKey = request.getHeaders().getFirst("X-API-Key");
        
        // If not in header, check query parameter
        if (apiKey == null) {
            URI uri = request.getUrl();
            String query = uri.getQuery();
            if (query != null && query.contains("api_key=")) {
                String[] params = query.split("&");
                for (String param : params) {
                    if (param.startsWith("api_key=")) {
                        apiKey = param.substring(8);
                        break;
                    }
                }
            }
        }

        if (apiKey == null || !apiKey.equals(validApiKey)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        return ResponseEntity.ok().build();
    }

    @Override
    public String getType() {
        return "apikey";
    }
} 