<?php

namespace Tests\Auth;

use Auth\SAMLAuth;

class SAMLAuthTest extends TestUtils
{
    private $auth;

    protected function setUp(): void
    {
        parent::setUp();
        $this->auth = new SAMLAuth(
            'test-entity-id',
            'test-assertion-consumer-service-url',
            'test-idp-sso-url',
            'test-idp-certificate'
        );
    }

    public function testValidSAMLResponse(): void
    {
        $request = $this->createTestRequest('POST', [
            'Content-Type' => 'application/x-www-form-urlencoded'
        ], 'SAMLResponse=test-saml-response');
        $this->runAuthTest($this->auth, $request, 200, false);
    }

    public function testInvalidSAMLResponse(): void
    {
        $request = $this->createTestRequest('POST', [
            'Content-Type' => 'application/x-www-form-urlencoded'
        ], 'SAMLResponse=invalid-saml-response');
        $this->runAuthTest($this->auth, $request, 401, true);
    }

    public function testMissingSAMLResponse(): void
    {
        $request = $this->createTestRequest('POST', [
            'Content-Type' => 'application/x-www-form-urlencoded'
        ], '');
        $this->runAuthTest($this->auth, $request, 401, true);
    }

    public function testInvalidContentType(): void
    {
        $request = $this->createTestRequest('POST', [
            'Content-Type' => 'application/json'
        ], '{}');
        $this->runAuthTest($this->auth, $request, 401, true);
    }

    public function testInvalidHTTPMethod(): void
    {
        $request = $this->createTestRequest('GET');
        $this->runAuthTest($this->auth, $request, 401, true);
    }

    public function testGetType(): void
    {
        $this->assertAuthType($this->auth, 'saml');
    }
} 