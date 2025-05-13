<?php

namespace Auth;

use Psr\Http\Message\ServerRequestInterface;

class NTLMAuth extends BaseAuth
{
    private string $username;
    private string $password;
    private string $domain;

    public function __construct(string $username, string $password, string $domain)
    {
        $this->type = AuthType::NTLM;
        $this->username = $username;
        $this->password = $password;
        $this->domain = $domain;
    }

    public function authenticate(ServerRequestInterface $request): bool
    {
        // TODO: Implement NTLM validation
        return true;
    }

    public function addAuth(ServerRequestInterface $request): ServerRequestInterface
    {
        // TODO: Add Authorization header
        return $request;
    }
} 