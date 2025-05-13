package com.auth;

import com.auth.base.Authentication;
import org.junit.jupiter.api.BeforeEach;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

public class TestUtils {
    @Mock
    protected RestTemplate restTemplate;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    protected RequestEntity<Void> createTestRequest(HttpMethod method, Map<String, String> headers) {
        HttpHeaders httpHeaders = new HttpHeaders();
        if (headers != null) {
            headers.forEach(httpHeaders::add);
        }
        return new RequestEntity<>(httpHeaders, method, URI.create("http://example.com"));
    }

    protected void runAuthTest(Authentication auth, RequestEntity<Void> request, HttpStatus expectedStatus, boolean expectError) {
        try {
            ResponseEntity<Void> response = auth.authenticate(request);
            if (expectError) {
                throw new AssertionError("Expected authentication error but none occurred");
            }
            if (response.getStatusCode() != expectedStatus) {
                throw new AssertionError("Expected status " + expectedStatus + " but got " + response.getStatusCode());
            }
        } catch (Exception e) {
            if (!expectError) {
                throw new AssertionError("Unexpected authentication error: " + e.getMessage());
            }
        }
    }

    protected void assertAuthType(Authentication auth, String expectedType) {
        if (!auth.getType().equals(expectedType)) {
            throw new AssertionError("Expected auth type " + expectedType + " but got " + auth.getType());
        }
    }
} 