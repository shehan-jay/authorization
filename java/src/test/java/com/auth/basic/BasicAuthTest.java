package com.auth.basic;

import com.auth.basic.BasicAuthApplication;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockFilterChain;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.FilterChain;
import java.io.IOException;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class BasicAuthTest {
    // Subclass to expose doFilterInternal for testing
    static class TestableBasicAuth extends BasicAuthApplication.BasicAuth {
        public void callDoFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
            super.doFilterInternal(request, response, chain);
        }
    }

    private TestableBasicAuth auth;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private MockFilterChain filterChain;

    @BeforeEach
    void setUp() {
        auth = new TestableBasicAuth();
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        filterChain = new MockFilterChain();
    }

    @Test
    void testAuthenticateValidCredentials() throws ServletException, IOException {
        String credentials = Base64.getEncoder().encodeToString("admin:password123".getBytes());
        request.addHeader("Authorization", "Basic " + credentials);

        auth.callDoFilterInternal(request, response, filterChain);
        assertEquals(200, response.getStatus());
    }

    @Test
    void testAuthenticateInvalidCredentials() throws ServletException, IOException {
        String credentials = Base64.getEncoder().encodeToString("admin:wrongpassword".getBytes());
        request.addHeader("Authorization", "Basic " + credentials);

        auth.callDoFilterInternal(request, response, filterChain);
        assertEquals(401, response.getStatus());
    }

    @Test
    void testAuthenticateMissingHeader() throws ServletException, IOException {
        auth.callDoFilterInternal(request, response, filterChain);
        assertEquals(401, response.getStatus());
    }

    @Test
    void testAuthenticateMalformedHeader() throws ServletException, IOException {
        request.addHeader("Authorization", "Basic invalid_base64");

        auth.callDoFilterInternal(request, response, filterChain);
        assertEquals(401, response.getStatus());
    }

    @Test
    void testGetPort() {
        assertEquals(8081, auth.getPort());
    }

    @Test
    void testSetPort() {
        int newPort = 8082;
        auth.setPort(newPort);
        assertEquals(newPort, auth.getPort());
    }
} 