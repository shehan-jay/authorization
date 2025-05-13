package com.auth;

import com.auth.base.Authentication;
import com.auth.saml.SAMLAuth;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class SAMLAuthTest extends TestUtils {
    private Authentication auth;

    @BeforeEach
    void setUp() {
        super.setUp();
        auth = new SAMLAuth("test-entity-id", "test-acs-url", "test-idp-sso-url", "test-idp-certificate");
    }

    @Test
    void testValidSAMLResponse() {
        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", MediaType.APPLICATION_FORM_URLENCODED_VALUE);
        RequestEntity<Void> request = createTestRequest(HttpMethod.POST, headers);
        runAuthTest(auth, request, HttpStatus.OK, false);
    }

    @Test
    void testInvalidEntityId() {
        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", MediaType.APPLICATION_FORM_URLENCODED_VALUE);
        RequestEntity<Void> request = createTestRequest(HttpMethod.POST, headers);
        runAuthTest(auth, request, HttpStatus.UNAUTHORIZED, true);
    }

    @Test
    void testInvalidACSUrl() {
        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", MediaType.APPLICATION_FORM_URLENCODED_VALUE);
        RequestEntity<Void> request = createTestRequest(HttpMethod.POST, headers);
        runAuthTest(auth, request, HttpStatus.UNAUTHORIZED, true);
    }

    @Test
    void testInvalidIdPCertificate() {
        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", MediaType.APPLICATION_FORM_URLENCODED_VALUE);
        RequestEntity<Void> request = createTestRequest(HttpMethod.POST, headers);
        runAuthTest(auth, request, HttpStatus.UNAUTHORIZED, true);
    }

    @Test
    void testMalformedSAMLResponse() {
        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", MediaType.APPLICATION_FORM_URLENCODED_VALUE);
        RequestEntity<Void> request = createTestRequest(HttpMethod.POST, headers);
        runAuthTest(auth, request, HttpStatus.BAD_REQUEST, true);
    }

    @Test
    void testInvalidHttpMethod() {
        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", MediaType.APPLICATION_FORM_URLENCODED_VALUE);
        RequestEntity<Void> request = createTestRequest(HttpMethod.GET, headers);
        runAuthTest(auth, request, HttpStatus.METHOD_NOT_ALLOWED, true);
    }

    @Test
    void testInvalidContentType() {
        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", MediaType.APPLICATION_JSON_VALUE);
        RequestEntity<Void> request = createTestRequest(HttpMethod.POST, headers);
        runAuthTest(auth, request, HttpStatus.UNSUPPORTED_MEDIA_TYPE, true);
    }

    @Test
    void testMissingContentType() {
        RequestEntity<Void> request = createTestRequest(HttpMethod.POST, null);
        runAuthTest(auth, request, HttpStatus.UNSUPPORTED_MEDIA_TYPE, true);
    }

    @Test
    void testGetType() {
        assertAuthType(auth, "saml");
    }
} 