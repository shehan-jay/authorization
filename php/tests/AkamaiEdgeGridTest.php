<?php

namespace Tests\Auth;

use Auth\AkamaiEdgeGrid;

class AkamaiEdgeGridTest extends TestUtils
{
    private $auth;

    protected function setUp(): void
    {
        parent::setUp();
        $this->auth = new AkamaiEdgeGrid('test-client-token', 'test-client-secret', 'test-access-token', 'test-host');
    }

    public function testValidEdgeGridCredentials(): void
    {
        $request = $this->createTestRequest('GET', [
            'Authorization' => 'EG1-HMAC-SHA256 client_token=test-client-token;' .
                'access_token=test-access-token;' .
                'timestamp=20240101T00:00:00+0000;' .
                'nonce=test-nonce;' .
                'signature=test-signature'
        ]);
        $this->runAuthTest($this->auth, $request, 200, false);
    }

    public function testInvalidClientToken(): void
    {
        $request = $this->createTestRequest('GET', [
            'Authorization' => 'EG1-HMAC-SHA256 client_token=wrong-client-token;' .
                'access_token=test-access-token;' .
                'timestamp=20240101T00:00:00+0000;' .
                'nonce=test-nonce;' .
                'signature=test-signature'
        ]);
        $this->runAuthTest($this->auth, $request, 401, true);
    }

    public function testMissingAuthorizationHeader(): void
    {
        $request = $this->createTestRequest('GET');
        $this->runAuthTest($this->auth, $request, 401, true);
    }

    public function testMalformedAuthorizationHeader(): void
    {
        $request = $this->createTestRequest('GET', [
            'Authorization' => 'EG1-HMAC-SHA256'
        ]);
        $this->runAuthTest($this->auth, $request, 401, true);
    }

    public function testInvalidScheme(): void
    {
        $request = $this->createTestRequest('GET', [
            'Authorization' => 'Basic dGVzdC11c2VyOnRlc3QtcGFzc3dvcmQ='
        ]);
        $this->runAuthTest($this->auth, $request, 401, true);
    }

    public function testGetType(): void
    {
        $this->assertAuthType($this->auth, 'akamai');
    }
} 