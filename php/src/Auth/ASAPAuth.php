<?php

namespace Auth;

use Psr\Http\Message\ServerRequestInterface;

class ASAPAuth extends BaseAuth
{
    private string $issuer;
    private string $audience;
    private string $privateKey;

    public function __construct(string $issuer, string $audience, string $privateKey)
    {
        $this->type = AuthType::ASAP;
        $this->issuer = $issuer;
        $this->audience = $audience;
        $this->privateKey = $privateKey;
    }

    public function authenticate(ServerRequestInterface $request): bool
    {
        // TODO: Implement ASAP validation
        return true;
    }

    public function addAuth(ServerRequestInterface $request): ServerRequestInterface
    {
        // TODO: Add Authorization header
        return $request;
    }
} 