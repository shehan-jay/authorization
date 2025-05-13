<?php

namespace Tests\Auth;

use Auth\JWTBearer;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class JWTBearerTest extends TestUtils
{
    private $auth;
    private $secretKey = 'test-secret-key';

    protected function setUp(): void
    {
        parent::setUp();
        $this->auth = new JWTBearer($this->secretKey);
    }

    private function createTestJWT(array $claims = []): string
    {
        $defaultClaims = [
            'sub' => 'test-user',
            'exp' => time() + 3600,
            'iat' => time()
        ];
        $claims = array_merge($defaultClaims, $claims);
        return JWT::encode($claims, $this->secretKey, 'HS256');
    }

    public function testValidJWT(): void
    {
        $token = $this->createTestJWT();
        $request = $this->createTestRequest('GET', [
            'Authorization' => 'Bearer ' . $token
        ]);
        $this->runAuthTest($this->auth, $request, 200, false);
    }

    public function testExpiredJWT(): void
    {
        $token = $this->createTestJWT(['exp' => time() - 3600]);
        $request = $this->createTestRequest('GET', [
            'Authorization' => 'Bearer ' . $token
        ]);
        $this->runAuthTest($this->auth, $request, 401, true);
    }

    public function testInvalidSignature(): void
    {
        $token = JWT::encode(['sub' => 'test-user'], 'wrong-secret-key', 'HS256');
        $request = $this->createTestRequest('GET', [
            'Authorization' => 'Bearer ' . $token
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
        $this->assertAuthType($this->auth, 'jwt');
    }
} 