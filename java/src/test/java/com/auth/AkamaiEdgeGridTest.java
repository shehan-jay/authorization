package com.auth;

import com.auth.base.Authentication;
import com.auth.akamai.AkamaiEdgeGrid;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.RequestEntity;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class AkamaiEdgeGridTest extends TestUtils {
    private Authentication auth;

    @BeforeEach
    void setUp() {
        super.setUp();
        auth = new AkamaiEdgeGrid("test-client-token", "test-client-secret", "test-access-token");
    }

    @Test
    void testValidEdgeGridCredentials() {
        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "EG1-HMAC-SHA256 client_token=\"test-client-token\"," +
            "access_token=\"test-access-token\"," +
            "timestamp=\"1234567890\"," +
            "nonce=\"test-nonce\"," +
            "signature=\"test-signature\"");
        RequestEntity<Void> request = createTestRequest(HttpMethod.GET, headers);
        runAuthTest(auth, request, HttpStatus.OK, false);
    }

    @Test
    void testInvalidClientToken() {
        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "EG1-HMAC-SHA256 client_token=\"wrong-token\"," +
            "access_token=\"test-access-token\"," +
            "timestamp=\"1234567890\"," +
            "nonce=\"test-nonce\"," +
            "signature=\"test-signature\"");
        RequestEntity<Void> request = createTestRequest(HttpMethod.GET, headers);
        runAuthTest(auth, request, HttpStatus.UNAUTHORIZED, true);
    }

    @Test
    void testMissingAuthorizationHeader() {
        RequestEntity<Void> request = createTestRequest(HttpMethod.GET, null);
        runAuthTest(auth, request, HttpStatus.UNAUTHORIZED, true);
    }

    @Test
    void testMalformedAuthorizationHeader() {
        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "EG1-HMAC-SHA256");
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
        assertAuthType(auth, "akamai");
    }
} 