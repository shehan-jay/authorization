<?php

namespace Tests\Auth;

use Auth\AWSSignature;

class AWSSignatureTest extends TestUtils
{
    private $auth;

    protected function setUp(): void
    {
        parent::setUp();
        $this->auth = new AWSSignature('test-access-key', 'test-secret-key', 'us-east-1', 's3');
    }

    public function testValidAWSSignature(): void
    {
        $request = $this->createTestRequest('GET', [
            'Authorization' => 'AWS4-HMAC-SHA256 ' .
                'Credential=test-access-key/20240101/us-east-1/s3/aws4_request, ' .
                'SignedHeaders=host;x-amz-date, ' .
                'Signature=test-signature',
            'X-Amz-Date' => '20240101T000000Z'
        ]);
        $this->runAuthTest($this->auth, $request, 200, false);
    }

    public function testInvalidAccessKey(): void
    {
        $request = $this->createTestRequest('GET', [
            'Authorization' => 'AWS4-HMAC-SHA256 ' .
                'Credential=wrong-access-key/20240101/us-east-1/s3/aws4_request, ' .
                'SignedHeaders=host;x-amz-date, ' .
                'Signature=test-signature',
            'X-Amz-Date' => '20240101T000000Z'
        ]);
        $this->runAuthTest($this->auth, $request, 401, true);
    }

    public function testMissingAuthorizationHeader(): void
    {
        $request = $this->createTestRequest('GET', [
            'X-Amz-Date' => '20240101T000000Z'
        ]);
        $this->runAuthTest($this->auth, $request, 401, true);
    }

    public function testMissingXAmzDateHeader(): void
    {
        $request = $this->createTestRequest('GET', [
            'Authorization' => 'AWS4-HMAC-SHA256 ' .
                'Credential=test-access-key/20240101/us-east-1/s3/aws4_request, ' .
                'SignedHeaders=host;x-amz-date, ' .
                'Signature=test-signature'
        ]);
        $this->runAuthTest($this->auth, $request, 401, true);
    }

    public function testMalformedAuthorizationHeader(): void
    {
        $request = $this->createTestRequest('GET', [
            'Authorization' => 'AWS4-HMAC-SHA256',
            'X-Amz-Date' => '20240101T000000Z'
        ]);
        $this->runAuthTest($this->auth, $request, 401, true);
    }

    public function testGetType(): void
    {
        $this->assertAuthType($this->auth, 'aws');
    }
} 