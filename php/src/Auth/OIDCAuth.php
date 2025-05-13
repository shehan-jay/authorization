<?php

namespace Auth;

use Psr\Http\Message\ServerRequestInterface;

class OIDCAuth extends BaseAuth
{
    private string $clientId;
    private string $clientSecret;
    private string $issuer;

    public function __construct(string $clientId, string $clientSecret, string $issuer)
    {
        $this->type = AuthType::OIDC;
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->issuer = $issuer;
    }

    public function authenticate(ServerRequestInterface $request): bool
    {
        // TODO: Implement OIDC validation
        return true;
    }

    public function addAuth(ServerRequestInterface $request): ServerRequestInterface
    {
        // TODO: Add Authorization header
        return $request;
    }
} 