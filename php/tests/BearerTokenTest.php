<?php

namespace Tests\Auth;

use Auth\BearerToken;

class BearerTokenTest extends TestUtils
{
    private $auth;

    protected function setUp(): void
    {
        parent::setUp();
        $this->auth = new BearerToken('valid-token');
    }

    public function testValidToken(): void
    {
        $request = $this->createTestRequest('GET', [
            'Authorization' => 'Bearer valid-token'
        ]);
        $this->runAuthTest($this->auth, $request, 200, false);
    }

    public function testInvalidToken(): void
    {
        $request = $this->createTestRequest('GET', [
            'Authorization' => 'Bearer invalid-token'
        ]);
        $this->runAuthTest($this->auth, $request, 401, true);
    }

    public function testMissingToken(): void
    {
        $request = $this->createTestRequest('GET');
        $this->runAuthTest($this->auth, $request, 401, true);
    }

    public function testMalformedHeader(): void
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
        $this->assertAuthType($this->auth, 'bearer');
    }
} 