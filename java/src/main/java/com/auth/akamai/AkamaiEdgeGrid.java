package com.auth.akamai;

import com.auth.base.Authentication;
import org.springframework.http.HttpStatus;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class AkamaiEdgeGrid implements Authentication {
    private final String clientToken;
    private final String clientSecret;
    private final String accessToken;

    public AkamaiEdgeGrid(String clientToken, String clientSecret, String accessToken) {
        this.clientToken = clientToken;
        this.clientSecret = clientSecret;
        this.accessToken = accessToken;
    }

    @Override
    public ResponseEntity<Void> authenticate(RequestEntity<Void> request) {
        String authHeader = request.getHeaders().getFirst("Authorization");
        if (authHeader == null || !authHeader.startsWith("EG1-HMAC-SHA256 ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        Map<String, String> edgeGridParams = parseEdgeGridHeader(authHeader);
        if (!validateEdgeGridParams(edgeGridParams)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        if (!edgeGridParams.get("client_token").equals(clientToken)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        // In a real implementation, we would verify the signature here
        // This is a simplified version that just checks the presence of the signature
        if (!edgeGridParams.containsKey("signature")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        return ResponseEntity.ok().build();
    }

    private Map<String, String> parseEdgeGridHeader(String authHeader) {
        Map<String, String> params = new HashMap<>();
        Pattern pattern = Pattern.compile("(\\w+)=\"([^\"]*)\"");
        Matcher matcher = pattern.matcher(authHeader);
        while (matcher.find()) {
            params.put(matcher.group(1), matcher.group(2));
        }
        return params;
    }

    private boolean validateEdgeGridParams(Map<String, String> params) {
        return params.containsKey("client_token") &&
               params.containsKey("access_token") &&
               params.containsKey("timestamp") &&
               params.containsKey("nonce") &&
               params.containsKey("signature");
    }

    @Override
    public String getType() {
        return "akamai";
    }
} 