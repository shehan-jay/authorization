<?php

namespace Tests\Auth;

use Auth\DigestAuth;

class DigestAuthTest extends TestUtils
{
    private $auth;

    protected function setUp(): void
    {
        parent::setUp();
        $this->auth = new DigestAuth('test-realm', 'test-user:test-password');
    }

    public function testValidDigestCredentials(): void
    {
        $request = $this->createTestRequest('GET', [
            'Authorization' => 'Digest username="test-user",' .
                'realm="test-realm",' .
                'nonce="test-nonce",' .
                'uri="/",' .
                'response="test-response",' .
                'algorithm=MD5,' .
                'qop=auth,' .
                'nc=00000001,' .
                'cnonce="test-cnonce"'
        ]);
        $this->runAuthTest($this->auth, $request, 200, false);
    }

    public function testInvalidUsername(): void
    {
        $request = $this->createTestRequest('GET', [
            'Authorization' => 'Digest username="wrong-user",' .
                'realm="test-realm",' .
                'nonce="test-nonce",' .
                'uri="/",' .
                'response="test-response",' .
                'algorithm=MD5,' .
                'qop=auth,' .
                'nc=00000001,' .
                'cnonce="test-cnonce"'
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
            'Authorization' => 'Digest'
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
        $this->assertAuthType($this->auth, 'digest');
    }
} 