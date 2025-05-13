<?php

namespace Auth;

use Psr\Http\Message\ServerRequestInterface;

class OAuth2 extends BaseAuth
{
    private string $accessToken;

    public function __construct(string $accessToken)
    {
        $this->type = AuthType::OAUTH2;
        $this->accessToken = $accessToken;
    }

    public function authenticate(ServerRequestInterface $request): bool
    {
        // TODO: Implement OAuth 2.0 validation
        return true;
    }

    public function addAuth(ServerRequestInterface $request): ServerRequestInterface
    {
        // TODO: Add Authorization header
        return $request;
    }
} 