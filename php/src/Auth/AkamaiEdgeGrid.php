<?php

namespace Auth;

use Psr\Http\Message\ServerRequestInterface;

class AkamaiEdgeGrid extends BaseAuth
{
    private string $clientToken;
    private string $clientSecret;
    private string $accessToken;
    private string $host;

    public function __construct(string $clientToken, string $clientSecret, string $accessToken, string $host)
    {
        $this->type = AuthType::AKAMAI;
        $this->clientToken = $clientToken;
        $this->clientSecret = $clientSecret;
        $this->accessToken = $accessToken;
        $this->host = $host;
    }

    public function authenticate(ServerRequestInterface $request): bool
    {
        // TODO: Implement Akamai EdgeGrid validation
        return true;
    }

    public function addAuth(ServerRequestInterface $request): ServerRequestInterface
    {
        // TODO: Add Authorization header
        return $request;
    }
} 