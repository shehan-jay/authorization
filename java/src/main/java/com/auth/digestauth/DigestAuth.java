package com.auth.digestauth;

import com.auth.base.Authentication;
import org.springframework.http.HttpStatus;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DigestAuth implements Authentication {
    private final String realm;
    private final Map<String, String> credentials;

    public DigestAuth(String realm, String credentials) {
        this.realm = realm;
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
        if (authHeader == null || !authHeader.startsWith("Digest ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        Map<String, String> authParams = parseAuthHeader(authHeader);
        if (!validateAuthParams(authParams)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        String username = authParams.get("username");
        if (!username.equals(credentials.get("username"))) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        String response = calculateResponse(authParams, request.getMethod().name());
        if (!response.equals(authParams.get("response"))) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        return ResponseEntity.ok().build();
    }

    private Map<String, String> parseAuthHeader(String authHeader) {
        Map<String, String> params = new HashMap<>();
        Pattern pattern = Pattern.compile("(\\w+)=\"([^\"]*)\"");
        Matcher matcher = pattern.matcher(authHeader);
        while (matcher.find()) {
            params.put(matcher.group(1), matcher.group(2));
        }
        return params;
    }

    private boolean validateAuthParams(Map<String, String> params) {
        return params.containsKey("username") &&
               params.containsKey("realm") &&
               params.containsKey("nonce") &&
               params.containsKey("uri") &&
               params.containsKey("response") &&
               params.containsKey("algorithm") &&
               params.containsKey("qop") &&
               params.containsKey("nc") &&
               params.containsKey("cnonce");
    }

    private String calculateResponse(Map<String, String> params, String method) {
        try {
            String ha1 = md5(params.get("username") + ":" + realm + ":" + credentials.get("password"));
            String ha2 = md5(method + ":" + params.get("uri"));
            return md5(ha1 + ":" + params.get("nonce") + ":" + params.get("nc") + ":" + 
                      params.get("cnonce") + ":" + params.get("qop") + ":" + ha2);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("MD5 algorithm not available", e);
        }
    }

    private String md5(String input) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] messageDigest = md.digest(input.getBytes());
        StringBuilder hexString = new StringBuilder();
        for (byte b : messageDigest) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    @Override
    public String getType() {
        return "digest";
    }
} 