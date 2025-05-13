package com.auth.aws;

import com.auth.base.Authentication;
import org.springframework.http.HttpStatus;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class AWSAuth implements Authentication {
    private final String accessKey;
    private final String secretKey;
    private final String region;

    private static final Pattern CREDENTIAL_PATTERN = Pattern.compile(
        "AWS4-HMAC-SHA256 Credential=([^/]+)/([^/]+)/([^/]+)/[^,]+," +
        "SignedHeaders=([^,]+)," +
        "Signature=([^,]+)"
    );

    public AWSAuth(String accessKey, String secretKey, String region) {
        this.accessKey = accessKey;
        this.secretKey = secretKey;
        this.region = region;
    }

    @Override
    public ResponseEntity<Void> authenticate(RequestEntity<Void> request) {
        String authHeader = request.getHeaders().getFirst("Authorization");
        String dateHeader = request.getHeaders().getFirst("X-Amz-Date");

        if (authHeader == null || !authHeader.startsWith("AWS4-HMAC-SHA256")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        if (dateHeader == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        Matcher matcher = CREDENTIAL_PATTERN.matcher(authHeader);
        if (!matcher.matches()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        String requestAccessKey = matcher.group(1);
        String requestDate = matcher.group(2);
        String requestRegion = matcher.group(3);
        String signedHeaders = matcher.group(4);
        String signature = matcher.group(5);

        // In a real implementation, this would:
        // 1. Verify the access key exists
        // 2. Calculate the expected signature using the secret key
        // 3. Compare the calculated signature with the provided one
        // 4. Verify the request is not expired
        // 5. Check if the signed headers match the request

        // For this example, we'll just check if the access key and region match
        if (requestAccessKey.equals(accessKey) && requestRegion.equals(region)) {
            return ResponseEntity.ok().build();
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }

    @Override
    public String getType() {
        return "aws";
    }
} 