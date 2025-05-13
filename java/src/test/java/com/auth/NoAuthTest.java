package com.auth;

import com.auth.base.Authentication;
import com.auth.none.NoAuth;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.RequestEntity;

import static org.junit.jupiter.api.Assertions.*;

class NoAuthTest extends TestUtils {
    private Authentication auth;

    @BeforeEach
    void setUp() {
        super.setUp();
        auth = new NoAuth();
    }

    @Test
    void testNoAuthenticationRequired() {
        RequestEntity<Void> request = createTestRequest(HttpMethod.GET, null);
        runAuthTest(auth, request, HttpStatus.OK, false);
    }

    @Test
    void testGetType() {
        assertAuthType(auth, "none");
    }
} 