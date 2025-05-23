<?php

namespace Tests\Auth;

use Auth\BasicAuth;

class BasicAuthTest extends TestUtils
{
    private $auth;

    protected function setUp(): void
    {
        parent::setUp();
        $this->auth = new BasicAuth('test-user', 'test-password');
    }

    public function testValidCredentials(): void
    {
        $request = $this->createTestRequest('GET', [
            'Authorization' => 'Basic ' . base64_encode('test-user:test-password')
        ]);
        $this->runAuthTest($this->auth, $request, 200, false);
    }

    public function testInvalidUsername(): void
    {
        $request = $this->createTestRequest('GET', [
            'Authorization' => 'Basic ' . base64_encode('wrong-user:test-password')
        ]);
        $this->runAuthTest($this->auth, $request, 401, true);
    }

    public function testInvalidPassword(): void
    {
        $request = $this->createTestRequest('GET', [
            'Authorization' => 'Basic ' . base64_encode('test-user:wrong-password')
        ]);
        $this->runAuthTest($this->auth, $request, 401, true);
    }

    public function testMissingCredentials(): void
    {
        $request = $this->createTestRequest('GET');
        $this->runAuthTest($this->auth, $request, 401, true);
    }

    public function testMalformedHeader(): void
    {
        $request = $this->createTestRequest('GET', [
            'Authorization' => 'Basic invalid-base64'
        ]);
        $this->runAuthTest($this->auth, $request, 401, true);
    }

    public function testInvalidScheme(): void
    {
        $request = $this->createTestRequest('GET', [
            'Authorization' => 'Bearer test-token'
        ]);
        $this->runAuthTest($this->auth, $request, 401, true);
    }

    public function testGetType(): void
    {
        $this->assertAuthType($this->auth, 'basic');
    }
} 