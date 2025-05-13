<?php

namespace Tests\Auth;

use Auth\ASAPAuth;

class ASAPAuthTest extends TestUtils
{
    private $auth;

    protected function setUp(): void
    {
        parent::setUp();
        $this->auth = new ASAPAuth('test-issuer', 'test-audience', 'test-private-key');
    }

    public function testValidASAPToken(): void
    {
        $request = $this->createTestRequest('GET', [
            'Authorization' => 'Bearer test-asap-token'
        ]);
        $this->runAuthTest($this->auth, $request, 200, false);
    }

    public function testInvalidASAPToken(): void
    {
        $request = $this->createTestRequest('GET', [
            'Authorization' => 'Bearer invalid-asap-token'
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
        $this->assertAuthType($this->auth, 'asap');
    }
} 