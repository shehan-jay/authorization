<?php

namespace Auth;

use Psr\Http\Message\ServerRequestInterface;

class JWTBearer extends BaseAuth
{
    private string $secret;

    public function __construct(string $secret)
    {
        $this->type = AuthType::JWT;
        $this->secret = $secret;
    }

    public function authenticate(ServerRequestInterface $request): bool
    {
        // TODO: Implement JWT validation
        return true;
    }

    public function addAuth(ServerRequestInterface $request): ServerRequestInterface
    {
        // TODO: Add Authorization header
        return $request;
    }
} 