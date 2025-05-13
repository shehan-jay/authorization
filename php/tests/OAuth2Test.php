<?php

namespace Tests\Auth;

use Auth\OAuth2;

class OAuth2Test extends TestUtils
{
    private $auth;

    protected function setUp(): void
    {
        parent::setUp();
        $this->auth = new OAuth2('test-client-id', 'test-client-secret');
    }

    public function testValidAccessToken(): void
    {
        $request = $this->createTestRequest('GET', [
            'Authorization' => 'Bearer valid-access-token'
        ]);
        $this->runAuthTest($this->auth, $request, 200, false);
    }

    public function testInvalidAccessToken(): void
    {
        $request = $this->createTestRequest('GET', [
            'Authorization' => 'Bearer invalid-access-token'
        ]);
        $this->runAuthTest($this->auth, $request, 401, true);
    }

    public function testMissingAccessToken(): void
    {
        $request = $this->createTestRequest('GET');
        $this->runAuthTest($this->auth, $request, 401, true);
    }

    public function testMalformedAuthorizationHeader(): void
    {
        $request = $this->createTestRequest('GET', [
            'Authorization' => 'Bearer'
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
        $this->assertAuthType($this->auth, 'oauth2');
    }
} 