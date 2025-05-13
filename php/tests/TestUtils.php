<?php

namespace Tests\Auth;

use PHPUnit\Framework\TestCase;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Exception\RequestException;

class TestUtils extends TestCase
{
    protected $mockHandler;
    protected $handlerStack;
    protected $client;

    protected function setUp(): void
    {
        $this->mockHandler = new MockHandler();
        $this->handlerStack = HandlerStack::create($this->mockHandler);
        $this->client = new Client(['handler' => $this->handlerStack]);
    }

    protected function createTestRequest(string $method = 'GET', array $headers = [], string $body = ''): Request
    {
        return new Request($method, 'http://example.com', $headers, $body);
    }

    protected function runAuthTest($auth, $request, $expectedStatus = 200, $expectedError = false): void
    {
        // Set up mock response
        $this->mockHandler->append(new Response($expectedStatus));

        try {
            // Authenticate the request
            $auth->authenticate($request);

            // If we expect an error but didn't get one, fail the test
            if ($expectedError) {
                $this->fail('Expected authentication error but none occurred');
            }
        } catch (\Exception $e) {
            // If we didn't expect an error but got one, fail the test
            if (!$expectedError) {
                $this->fail('Unexpected authentication error: ' . $e->getMessage());
            }
        }
    }

    protected function assertAuthType($auth, $expectedType): void
    {
        $this->assertEquals($expectedType, $auth->getType());
    }
} 