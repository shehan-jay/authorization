<?php

namespace Tests\Auth;

use Auth\OAuth1;

class OAuth1Test extends TestUtils
{
    private $auth;

    protected function setUp(): void
    {
        parent::setUp();
        $this->auth = new OAuth1(
            'test-consumer-key',
            'test-consumer-secret',
            'test-token',
            'test-token-secret'
        );
    }

    public function testValidOAuth1Signature(): void
    {
        $request = $this->createTestRequest('GET', [
            'Authorization' => 'OAuth oauth_consumer_key="test-consumer-key",' .
                'oauth_nonce="test-nonce",' .
                'oauth_signature="test-signature",' .
                'oauth_signature_method="HMAC-SHA1",' .
                'oauth_timestamp="1234567890",' .
                'oauth_token="test-token",' .
                'oauth_version="1.0"'
        ]);
        $this->runAuthTest($this->auth, $request, 200, false);
    }

    public function testInvalidConsumerKey(): void
    {
        $request = $this->createTestRequest('GET', [
            'Authorization' => 'OAuth oauth_consumer_key="wrong-key",' .
                'oauth_nonce="test-nonce",' .
                'oauth_signature="test-signature",' .
                'oauth_signature_method="HMAC-SHA1",' .
                'oauth_timestamp="1234567890",' .
                'oauth_token="test-token",' .
                'oauth_version="1.0"'
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
            'Authorization' => 'OAuth'
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
        $this->assertAuthType($this->auth, 'oauth1');
    }
} 