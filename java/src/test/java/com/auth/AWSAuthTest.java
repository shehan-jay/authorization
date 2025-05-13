package com.auth;

import com.auth.base.Authentication;
import com.auth.aws.AWSAuth;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.RequestEntity;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class AWSAuthTest extends TestUtils {
    private Authentication auth;

    @BeforeEach
    void setUp() {
        super.setUp();
        auth = new AWSAuth("test-access-key", "test-secret-key", "test-region");
    }

    @Test
    void testValidAWSCredentials() {
        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "AWS4-HMAC-SHA256 Credential=test-access-key/20240101/test-region/s3/aws4_request," +
            "SignedHeaders=host;x-amz-date," +
            "Signature=test-signature");
        headers.put("X-Amz-Date", "20240101T000000Z");
        RequestEntity<Void> request = createTestRequest(HttpMethod.GET, headers);
        runAuthTest(auth, request, HttpStatus.OK, false);
    }

    @Test
    void testInvalidAccessKey() {
        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "AWS4-HMAC-SHA256 Credential=wrong-access-key/20240101/test-region/s3/aws4_request," +
            "SignedHeaders=host;x-amz-date," +
            "Signature=test-signature");
        headers.put("X-Amz-Date", "20240101T000000Z");
        RequestEntity<Void> request = createTestRequest(HttpMethod.GET, headers);
        runAuthTest(auth, request, HttpStatus.UNAUTHORIZED, true);
    }

    @Test
    void testInvalidSignature() {
        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "AWS4-HMAC-SHA256 Credential=test-access-key/20240101/test-region/s3/aws4_request," +
            "SignedHeaders=host;x-amz-date," +
            "Signature=invalid-signature");
        headers.put("X-Amz-Date", "20240101T000000Z");
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
        headers.put("Authorization", "AWS4-HMAC-SHA256");
        headers.put("X-Amz-Date", "20240101T000000Z");
        RequestEntity<Void> request = createTestRequest(HttpMethod.GET, headers);
        runAuthTest(auth, request, HttpStatus.UNAUTHORIZED, true);
    }

    @Test
    void testMissingDateHeader() {
        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "AWS4-HMAC-SHA256 Credential=test-access-key/20240101/test-region/s3/aws4_request," +
            "SignedHeaders=host;x-amz-date," +
            "Signature=test-signature");
        RequestEntity<Void> request = createTestRequest(HttpMethod.GET, headers);
        runAuthTest(auth, request, HttpStatus.UNAUTHORIZED, true);
    }

    @Test
    void testInvalidScheme() {
        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "Basic dGVzdC11c2VyOnRlc3QtcGFzc3dvcmQ=");
        headers.put("X-Amz-Date", "20240101T000000Z");
        RequestEntity<Void> request = createTestRequest(HttpMethod.GET, headers);
        runAuthTest(auth, request, HttpStatus.UNAUTHORIZED, true);
    }

    @Test
    void testGetType() {
        assertAuthType(auth, "aws");
    }
} 