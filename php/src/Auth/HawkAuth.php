<?php

namespace Auth;

use Psr\Http\Message\ServerRequestInterface;

class HawkAuth extends BaseAuth
{
    private string $id;
    private string $key;
    private string $algorithm;

    public function __construct(string $id, string $key, string $algorithm)
    {
        $this->type = AuthType::HAWK;
        $this->id = $id;
        $this->key = $key;
        $this->algorithm = $algorithm;
    }

    public function authenticate(ServerRequestInterface $request): bool
    {
        // TODO: Implement Hawk validation
        return true;
    }

    public function addAuth(ServerRequestInterface $request): ServerRequestInterface
    {
        // TODO: Add Authorization header
        return $request;
    }
} 