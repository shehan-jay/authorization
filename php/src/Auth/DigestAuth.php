<?php

namespace Auth;

use Psr\Http\Message\ServerRequestInterface;

class DigestAuth extends BaseAuth
{
    private string $username;
    private string $password;

    public function __construct(string $username, string $password)
    {
        $this->type = AuthType::DIGEST;
        $this->username = $username;
        $this->password = $password;
    }

    public function authenticate(ServerRequestInterface $request): bool
    {
        // TODO: Implement Digest validation
        return true;
    }

    public function addAuth(ServerRequestInterface $request): ServerRequestInterface
    {
        // TODO: Add Authorization header
        return $request;
    }
} 