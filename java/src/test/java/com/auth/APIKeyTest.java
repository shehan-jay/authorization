package com.auth;

import com.auth.base.Authentication;
import com.auth.apikey.APIKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.RequestEntity;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class APIKeyTest extends TestUtils {
    private Authentication auth;

    @BeforeEach
    void setUp() {
        super.setUp();
        auth = new APIKey("valid-api-key");
    }

    @Test
    void testValidApiKeyInHeader() {
        Map<String, String> headers = new HashMap<>();
        headers.put("X-API-Key", "valid-api-key");
        RequestEntity<Void> request = createTestRequest(HttpMethod.GET, headers);
        runAuthTest(auth, request, HttpStatus.OK, false);
    }

    @Test
    void testValidApiKeyInQuery() {
        RequestEntity<Void> request = createTestRequest(HttpMethod.GET, null);
        request = new RequestEntity<>(request.getHeaders(), request.getMethod(), 
            request.getUrl().resolve("?api_key=valid-api-key"));
        runAuthTest(auth, request, HttpStatus.OK, false);
    }

    @Test
    void testInvalidApiKey() {
        Map<String, String> headers = new HashMap<>();
        headers.put("X-API-Key", "invalid-api-key");
        RequestEntity<Void> request = createTestRequest(HttpMethod.GET, headers);
        runAuthTest(auth, request, HttpStatus.UNAUTHORIZED, true);
    }

    @Test
    void testMissingApiKey() {
        RequestEntity<Void> request = createTestRequest(HttpMethod.GET, null);
        runAuthTest(auth, request, HttpStatus.UNAUTHORIZED, true);
    }

    @Test
    void testGetType() {
        assertAuthType(auth, "apikey");
    }
} 