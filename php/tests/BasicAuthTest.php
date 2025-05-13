<?php

namespace Auth\Tests;

use PHPUnit\Framework\TestCase;
use Auth\BasicAuth;
use GuzzleHttp\Psr7\ServerRequest;
use GuzzleHttp\Psr7\Response;
use Psr\Http\Message\ResponseInterface;

class BasicAuthTest extends TestCase
{
    private BasicAuth $auth;

    protected function setUp(): void
    {
        $this->auth = new BasicAuth("admin", "password123");
    }

    public function testAuthenticateValidCredentials(): void
    {
        $credentials = base64_encode('admin:password123');
        $request = new ServerRequest(
            'GET',
            '/api/secure',
            ['Authorization' => "Basic {$credentials}"]
        );

        $this->assertTrue($this->auth->authenticate($request));
    }

    public function testAuthenticateInvalidCredentials(): void
    {
        $credentials = base64_encode('admin:wrongpassword');
        $request = new ServerRequest(
            'GET',
            '/api/secure',
            ['Authorization' => "Basic {$credentials}"]
        );

        $this->assertFalse($this->auth->authenticate($request));
    }

    public function testAuthenticateMissingHeader(): void
    {
        $request = new ServerRequest('GET', '/api/secure');
        $this->assertFalse($this->auth->authenticate($request));
    }

    public function testAuthenticateMalformedHeader(): void
    {
        $request = new ServerRequest(
            'GET',
            '/api/secure',
            ['Authorization' => 'Basic invalid_base64']
        );

        $this->assertFalse($this->auth->authenticate($request));
    }

    public function testProcessMiddleware(): void
    {
        $credentials = base64_encode('admin:password123');
        $request = new ServerRequest(
            'GET',
            '/api/secure',
            ['Authorization' => "Basic {$credentials}"]
        );

        $handler = new class implements \Psr\Http\Server\RequestHandlerInterface {
            public function handle(\Psr\Http\Message\ServerRequestInterface $request): ResponseInterface
            {
                return new Response(200, [], 'Success');
            }
        };

        $auth = new BasicAuth("admin", "password123");
        $response = $auth->process($request, $handler);
        $this->assertEquals(200, $response->getStatusCode());
    }

    public function testProcessMiddlewareUnauthorized(): void
    {
        $request = new ServerRequest('GET', '/api/secure');
        $handler = new class implements \Psr\Http\Server\RequestHandlerInterface {
            public function handle(\Psr\Http\Message\ServerRequestInterface $request): ResponseInterface
            {
                return new Response(200, [], 'Success');
            }
        };

        $auth = new BasicAuth("admin", "password123");
        $response = $auth->process($request, $handler);
        $this->assertEquals(401, $response->getStatusCode());
    }

    public function testGetType(): void
    {
        $this->assertEquals('basic', $this->auth->getType());
    }
} 