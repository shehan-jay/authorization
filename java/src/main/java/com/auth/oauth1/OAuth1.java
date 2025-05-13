package com.auth.oauth1;

import com.auth.base.Authentication;
import org.springframework.http.HttpStatus;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class OAuth1 implements Authentication {
    private final String consumerKey;
    private final String consumerSecret;
    private final String token;
    private final String tokenSecret;

    public OAuth1(String consumerKey, String consumerSecret, String token, String tokenSecret) {
        this.consumerKey = consumerKey;
        this.consumerSecret = consumerSecret;
        this.token = token;
        this.tokenSecret = tokenSecret;
    }

    @Override
    public ResponseEntity<Void> authenticate(RequestEntity<Void> request) {
        String authHeader = request.getHeaders().getFirst("Authorization");
        if (authHeader == null || !authHeader.startsWith("OAuth ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        Map<String, String> oauthParams = parseOAuthHeader(authHeader);
        if (!validateOAuthParams(oauthParams)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        if (!oauthParams.get("oauth_consumer_key").equals(consumerKey)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        if (!oauthParams.get("oauth_token").equals(token)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        // In a real implementation, we would verify the signature here
        // This is a simplified version that just checks the presence of the signature
        if (!oauthParams.containsKey("oauth_signature")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        return ResponseEntity.ok().build();
    }

    private Map<String, String> parseOAuthHeader(String authHeader) {
        Map<String, String> params = new HashMap<>();
        Pattern pattern = Pattern.compile("(\\w+)=\"([^\"]*)\"");
        Matcher matcher = pattern.matcher(authHeader);
        while (matcher.find()) {
            params.put(matcher.group(1), matcher.group(2));
        }
        return params;
    }

    private boolean validateOAuthParams(Map<String, String> params) {
        return params.containsKey("oauth_consumer_key") &&
               params.containsKey("oauth_nonce") &&
               params.containsKey("oauth_signature") &&
               params.containsKey("oauth_signature_method") &&
               params.containsKey("oauth_timestamp") &&
               params.containsKey("oauth_token") &&
               params.containsKey("oauth_version");
    }

    @Override
    public String getType() {
        return "oauth1";
    }
} 