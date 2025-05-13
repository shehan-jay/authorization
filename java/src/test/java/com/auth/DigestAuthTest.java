package com.auth;

import com.auth.base.Authentication;
import com.auth.digestauth.DigestAuth;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.RequestEntity;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class DigestAuthTest extends TestUtils {
    private Authentication auth;

    @BeforeEach
    void setUp() {
        super.setUp();
        auth = new DigestAuth("test-realm", "test-user:test-password");
    }

    @Test
    void testValidDigestCredentials() {
        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "Digest username=\"test-user\"," +
            "realm=\"test-realm\"," +
            "nonce=\"test-nonce\"," +
            "uri=\"/\"," +
            "response=\"test-response\"," +
            "algorithm=MD5," +
            "qop=auth," +
            "nc=00000001," +
            "cnonce=\"test-cnonce\"");
        RequestEntity<Void> request = createTestRequest(HttpMethod.GET, headers);
        runAuthTest(auth, request, HttpStatus.OK, false);
    }

    @Test
    void testInvalidUsername() {
        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "Digest username=\"wrong-user\"," +
            "realm=\"test-realm\"," +
            "nonce=\"test-nonce\"," +
            "uri=\"/\"," +
            "response=\"test-response\"," +
            "algorithm=MD5," +
            "qop=auth," +
            "nc=00000001," +
            "cnonce=\"test-cnonce\"");
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
        headers.put("Authorization", "Digest");
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
        assertAuthType(auth, "digest");
    }
} 