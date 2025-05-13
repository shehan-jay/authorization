<?php

namespace Auth;

use Psr\Http\Message\ServerRequestInterface;

/**
 * BasicAuth implementation for HTTP Basic Authentication
 */
class BasicAuth extends BaseAuth
{
    private string $username;
    private string $password;

    /**
     * Create a new BasicAuth instance
     * @param string $username
     * @param string $password
     */
    public function __construct(string $username, string $password)
    {
        $this->type = AuthType::BASIC;
        $this->username = $username;
        $this->password = $password;
    }

    /**
     * Authenticate the request using Basic Authentication
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
        if (count($parts) !== 2 || $parts[0] !== 'Basic') {
            return false;
        }

        $decoded = base64_decode($parts[1]);
        if ($decoded === false) {
            return false;
        }

        $credentials = explode(':', $decoded);
        if (count($credentials) !== 2) {
            return false;
        }

        return $credentials[0] === $this->username && $credentials[1] === $this->password;
    }

    /**
     * Add Basic Authentication to the request
     * @param ServerRequestInterface $request
     * @return ServerRequestInterface
     */
    public function addAuth(ServerRequestInterface $request): ServerRequestInterface
    {
        $auth = base64_encode($this->username . ':' . $this->password);
        return $request->withHeader('Authorization', 'Basic ' . $auth);
    }
} 