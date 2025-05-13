<?php

namespace Tests\Auth;

use Auth\NoAuth;

class NoAuthTest extends TestUtils
{
    private $auth;

    protected function setUp(): void
    {
        parent::setUp();
        $this->auth = new NoAuth();
    }

    public function testNoAuthenticationRequired(): void
    {
        $request = $this->createTestRequest('GET');
        $this->runAuthTest($this->auth, $request, 200, false);
    }

    public function testRequestWithHeaders(): void
    {
        $request = $this->createTestRequest('GET', [
            'Authorization' => 'Bearer test-token'
        ]);
        $this->runAuthTest($this->auth, $request, 200, false);
    }

    public function testRequestWithQueryParameters(): void
    {
        $request = $this->createTestRequest('GET', [
            'X-API-Key' => 'test-api-key'
        ]);
        $this->runAuthTest($this->auth, $request, 200, false);
    }

    public function testGetType(): void
    {
        $this->assertAuthType($this->auth, 'none');
    }
} 