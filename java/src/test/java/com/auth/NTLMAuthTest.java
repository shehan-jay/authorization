package com.auth;

import com.auth.base.Authentication;
import com.auth.ntlm.NTLMAuth;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.RequestEntity;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class NTLMAuthTest extends TestUtils {
    private Authentication auth;

    @BeforeEach
    void setUp() {
        super.setUp();
        auth = new NTLMAuth("test-domain", "test-username", "test-password");
    }

    @Test
    void testValidNTLMCredentials() {
        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==");
        RequestEntity<Void> request = createTestRequest(HttpMethod.GET, headers);
        runAuthTest(auth, request, HttpStatus.OK, false);
    }

    @Test
    void testInvalidNTLMCredentials() {
        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "NTLM invalid-ntlm-token");
        RequestEntity<Void> request = createTestRequest(HttpMethod.GET, headers);
        runAuthTest(auth, request, HttpStatus.UNAUTHORIZED, true);
    }

    @Test
    void testInvalidDomain() {
        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==");
        RequestEntity<Void> request = createTestRequest(HttpMethod.GET, headers);
        runAuthTest(auth, request, HttpStatus.UNAUTHORIZED, true);
    }

    @Test
    void testInvalidUsername() {
        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==");
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
        headers.put("Authorization", "NTLM");
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
        assertAuthType(auth, "ntlm");
    }
} 