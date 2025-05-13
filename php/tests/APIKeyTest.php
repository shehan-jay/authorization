<?php

namespace Tests\Auth;

use Auth\APIKey;

class APIKeyTest extends TestUtils
{
    private $auth;

    protected function setUp(): void
    {
        parent::setUp();
        $this->auth = new APIKey('valid-api-key');
    }

    public function testValidApiKeyInHeader(): void
    {
        $request = $this->createTestRequest('GET', [
            'X-API-Key' => 'valid-api-key'
        ]);
        $this->runAuthTest($this->auth, $request, 200, false);
    }

    public function testValidApiKeyInQuery(): void
    {
        $request = $this->createTestRequest('GET');
        $request = $request->withUri($request->getUri()->withQuery('api_key=valid-api-key'));
        $this->runAuthTest($this->auth, $request, 200, false);
    }

    public function testInvalidApiKey(): void
    {
        $request = $this->createTestRequest('GET', [
            'X-API-Key' => 'invalid-api-key'
        ]);
        $this->runAuthTest($this->auth, $request, 401, true);
    }

    public function testMissingApiKey(): void
    {
        $request = $this->createTestRequest('GET');
        $this->runAuthTest($this->auth, $request, 401, true);
    }

    public function testGetType(): void
    {
        $this->assertAuthType($this->auth, 'apikey');
    }
} 