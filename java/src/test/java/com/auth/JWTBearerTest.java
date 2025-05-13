package com.auth;

import com.auth.base.Authentication;
import com.auth.jwtbearer.JWTBearer;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.RequestEntity;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class JWTBearerTest extends TestUtils {
    private Authentication auth;
    private String secretKey = "test-secret-key";

    @BeforeEach
    void setUp() {
        super.setUp();
        auth = new JWTBearer(secretKey);
    }

    private String createTestJWT(Map<String, Object> claims) {
        Map<String, Object> defaultClaims = new HashMap<>();
        defaultClaims.put("sub", "test-user");
        defaultClaims.put("exp", new Date(System.currentTimeMillis() + 3600000));
        defaultClaims.put("iat", new Date());
        defaultClaims.putAll(claims);

        return Jwts.builder()
                .setClaims(defaultClaims)
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact();
    }

    @Test
    void testValidJWT() {
        String token = createTestJWT(new HashMap<>());
        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "Bearer " + token);
        RequestEntity<Void> request = createTestRequest(HttpMethod.GET, headers);
        runAuthTest(auth, request, HttpStatus.OK, false);
    }

    @Test
    void testExpiredJWT() {
        Map<String, Object> claims = new HashMap<>();
        claims.put("exp", new Date(System.currentTimeMillis() - 3600000));
        String token = createTestJWT(claims);
        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "Bearer " + token);
        RequestEntity<Void> request = createTestRequest(HttpMethod.GET, headers);
        runAuthTest(auth, request, HttpStatus.UNAUTHORIZED, true);
    }

    @Test
    void testInvalidSignature() {
        String token = Jwts.builder()
                .setSubject("test-user")
                .signWith(SignatureAlgorithm.HS256, "wrong-secret-key")
                .compact();
        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "Bearer " + token);
        RequestEntity<Void> request = createTestRequest(HttpMethod.GET, headers);
        runAuthTest(auth, request, HttpStatus.UNAUTHORIZED, true);
    }

    @Test
    void testMissingToken() {
        RequestEntity<Void> request = createTestRequest(HttpMethod.GET, null);
        runAuthTest(auth, request, HttpStatus.UNAUTHORIZED, true);
    }

    @Test
    void testMalformedHeader() {
        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "Bearer");
        RequestEntity<Void> request = createTestRequest(HttpMethod.GET, headers);
        runAuthTest(auth, request, HttpStatus.UNAUTHORIZED, true);
    }

    @Test
    void testInvalidScheme() {
        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "Basic dGVzdC11c2VyOnRlc3QtcGFzc3dvcmQ=");
        RequestEntity<Void> request = createTestRequest(HttpMethod.GET, headers);
        runAuthTest(auth, request, HttpStatus.UNAUTHORIZED, true);
    }

    @Test
    void testGetType() {
        assertAuthType(auth, "jwt");
    }
} 