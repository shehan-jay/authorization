<?php

namespace Auth;

use Psr\Http\Message\ServerRequestInterface;

class OAuth1 extends BaseAuth
{
    private string $consumerKey;
    private string $consumerSecret;
    private string $token;
    private string $tokenSecret;

    public function __construct(string $consumerKey, string $consumerSecret, string $token, string $tokenSecret)
    {
        $this->type = AuthType::OAUTH1;
        $this->consumerKey = $consumerKey;
        $this->consumerSecret = $consumerSecret;
        $this->token = $token;
        $this->tokenSecret = $tokenSecret;
    }

    public function authenticate(ServerRequestInterface $request): bool
    {
        // TODO: Implement OAuth 1.0 validation
        return true;
    }

    public function addAuth(ServerRequestInterface $request): ServerRequestInterface
    {
        // TODO: Add Authorization header
        return $request;
    }
} 