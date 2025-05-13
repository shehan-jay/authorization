package com.auth.hawk;

import com.auth.base.Authentication;
import org.springframework.http.HttpStatus;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class HawkAuth implements Authentication {
    private final String hawkId;
    private final String hawkKey;

    public HawkAuth(String hawkId, String hawkKey) {
        this.hawkId = hawkId;
        this.hawkKey = hawkKey;
    }

    @Override
    public ResponseEntity<Void> authenticate(RequestEntity<Void> request) {
        String authHeader = request.getHeaders().getFirst("Authorization");
        if (authHeader == null || !authHeader.startsWith("Hawk ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        Map<String, String> hawkParams = parseHawkHeader(authHeader);
        if (!validateHawkParams(hawkParams)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        if (!hawkParams.get("id").equals(hawkId)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        // In a real implementation, we would verify the MAC here
        // This is a simplified version that just checks the presence of the MAC
        if (!hawkParams.containsKey("mac")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        return ResponseEntity.ok().build();
    }

    private Map<String, String> parseHawkHeader(String authHeader) {
        Map<String, String> params = new HashMap<>();
        Pattern pattern = Pattern.compile("(\\w+)=\"([^\"]*)\"");
        Matcher matcher = pattern.matcher(authHeader);
        while (matcher.find()) {
            params.put(matcher.group(1), matcher.group(2));
        }
        return params;
    }

    private boolean validateHawkParams(Map<String, String> params) {
        return params.containsKey("id") &&
               params.containsKey("ts") &&
               params.containsKey("nonce") &&
               params.containsKey("mac");
    }

    @Override
    public String getType() {
        return "hawk";
    }
} 