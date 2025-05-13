<?php

namespace Auth;

use Psr\Http\Message\ServerRequestInterface;

class APIKey extends BaseAuth
{
    private string $key;

    public function __construct(string $key)
    {
        $this->type = AuthType::API_KEY;
        $this->key = $key;
    }

    public function authenticate(ServerRequestInterface $request): bool
    {
        // TODO: Implement API Key validation
        return true;
    }

    public function addAuth(ServerRequestInterface $request): ServerRequestInterface
    {
        // TODO: Add API Key header
        return $request;
    }
} 