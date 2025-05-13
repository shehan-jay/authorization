<?php

namespace Tests\Auth;

use Auth\HawkAuth;

class HawkAuthTest extends TestUtils
{
    private $auth;

    protected function setUp(): void
    {
        parent::setUp();
        $this->auth = new HawkAuth('test-hawk-id', 'test-hawk-key', 'sha256');
    }

    public function testValidHawkCredentials(): void
    {
        $request = $this->createTestRequest('GET', [
            'Authorization' => 'Hawk id="test-hawk-id",' .
                'ts="1234567890",' .
                'nonce="test-nonce",' .
                'mac="test-mac",' .
                'hash="test-hash"'
        ]);
        $this->runAuthTest($this->auth, $request, 200, false);
    }

    public function testInvalidHawkID(): void
    {
        $request = $this->createTestRequest('GET', [
            'Authorization' => 'Hawk id="wrong-hawk-id",' .
                'ts="1234567890",' .
                'nonce="test-nonce",' .
                'mac="test-mac",' .
                'hash="test-hash"'
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
            'Authorization' => 'Hawk'
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
        $this->assertAuthType($this->auth, 'hawk');
    }
} 