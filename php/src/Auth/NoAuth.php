<?php

namespace Auth;

use Psr\Http\Message\ServerRequestInterface;

/**
 * NoAuth implementation that requires no authentication
 */
class NoAuth extends BaseAuth
{
    public function __construct()
    {
        $this->type = AuthType::NONE;
    }

    /**
     * Authenticate the request (always returns true as no auth is required)
     * @param ServerRequestInterface $request
     * @return bool
     */
    public function authenticate(ServerRequestInterface $request): bool
    {
        return true;
    }
} 