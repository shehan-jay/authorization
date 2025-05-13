<?php

namespace Tests\Auth;

use Auth\OIDCAuth;

class OIDCAuthTest extends TestUtils
{
    private $auth;

    protected function setUp(): void
    {
        parent::setUp();
        $this->auth = new OIDCAuth(
            'test-issuer',
            'test-client-id',
            'test-client-secret',
            ['test-audience']
        );
    }

    public function testValidIDToken(): void
    {
        $request = $this->createTestRequest('GET', [
            'Authorization' => 'Bearer test-id-token'
        ]);
        $this->runAuthTest($this->auth, $request, 200, false);
    }

    public function testInvalidIDToken(): void
    {
        $request = $this->createTestRequest('GET', [
            'Authorization' => 'Bearer invalid-id-token'
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
        $this->assertAuthType($this->auth, 'oidc');
    }
} 