package com.auth;

import com.auth.base.Authentication;
import com.auth.oauth1.OAuth1;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.RequestEntity;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class OAuth1Test extends TestUtils {
    private Authentication auth;

    @BeforeEach
    void setUp() {
        super.setUp();
        auth = new OAuth1(
            "test-consumer-key",
            "test-consumer-secret",
            "test-token",
            "test-token-secret"
        );
    }

    @Test
    void testValidOAuth1Signature() {
        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "OAuth oauth_consumer_key=\"test-consumer-key\"," +
            "oauth_nonce=\"test-nonce\"," +
            "oauth_signature=\"test-signature\"," +
            "oauth_signature_method=\"HMAC-SHA1\"," +
            "oauth_timestamp=\"1234567890\"," +
            "oauth_token=\"test-token\"," +
            "oauth_version=\"1.0\"");
        RequestEntity<Void> request = createTestRequest(HttpMethod.GET, headers);
        runAuthTest(auth, request, HttpStatus.OK, false);
    }

    @Test
    void testInvalidConsumerKey() {
        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "OAuth oauth_consumer_key=\"wrong-key\"," +
            "oauth_nonce=\"test-nonce\"," +
            "oauth_signature=\"test-signature\"," +
            "oauth_signature_method=\"HMAC-SHA1\"," +
            "oauth_timestamp=\"1234567890\"," +
            "oauth_token=\"test-token\"," +
            "oauth_version=\"1.0\"");
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
        headers.put("Authorization", "OAuth");
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
        assertAuthType(auth, "oauth1");
    }
} 