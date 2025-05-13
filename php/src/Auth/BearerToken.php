<?php

namespace Auth;

use Psr\Http\Message\ServerRequestInterface;

/**
 * BearerToken implementation for Bearer Token Authentication
 */
class BearerToken extends BaseAuth
{
    private string $token;

    /**
     * Create a new BearerToken instance
     * @param string $token
     */
    public function __construct(string $token)
    {
        $this->type = AuthType::BEARER;
        $this->token = $token;
    }

    /**
     * Authenticate the request using Bearer Token
     * @param ServerRequestInterface $request
     * @return bool
     */
    public function authenticate(ServerRequestInterface $request): bool
    {
        $auth = $request->getHeaderLine('Authorization');
        if (empty($auth)) {
            return false;
        }

        $parts = explode(' ', $auth);
        if (count($parts) !== 2 || $parts[0] !== 'Bearer') {
            return false;
        }

        return $parts[1] === $this->token;
    }

    /**
     * Add Bearer Token to the request
     * @param ServerRequestInterface $request
     * @return ServerRequestInterface
     */
    public function addAuth(ServerRequestInterface $request): ServerRequestInterface
    {
        return $request->withHeader('Authorization', 'Bearer ' . $this->token);
    }
} 