<?php

namespace Auth;

use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Authentication types
 */
class AuthType
{
    public const NONE = 'none';
    public const BASIC = 'basic';
    public const BEARER = 'bearer';
    public const JWT = 'jwt';
    public const DIGEST = 'digest';
    public const OAUTH1 = 'oauth1';
    public const OAUTH2 = 'oauth2';
    public const HAWK = 'hawk';
    public const AWS = 'aws';
    public const NTLM = 'ntlm';
    public const API_KEY = 'apikey';
    public const AKAMAI = 'akamai';
    public const ASAP = 'asap';
    public const OIDC = 'oidc';
    public const SAML = 'saml';
}

/**
 * Interface for all authentication methods
 */
interface AuthenticatorInterface
{
    /**
     * Authenticate the request
     * @param ServerRequestInterface $request
     * @return bool
     */
    public function authenticate(ServerRequestInterface $request): bool;

    /**
     * Get the authentication type
     * @return string
     */
    public function getType(): string;
}

/**
 * Base class for all authentication methods
 */
abstract class BaseAuth implements AuthenticatorInterface, MiddlewareInterface
{
    protected string $type;

    /**
     * Get the authentication type
     * @return string
     */
    public function getType(): string
    {
        return $this->type;
    }

    /**
     * Process the request through the authentication middleware
     * @param ServerRequestInterface $request
     * @param RequestHandlerInterface $handler
     * @return ResponseInterface
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if (!$this->authenticate($request)) {
            return new \GuzzleHttp\Psr7\Response(401, [], 'Unauthorized');
        }
        return $handler->handle($request);
    }
} 