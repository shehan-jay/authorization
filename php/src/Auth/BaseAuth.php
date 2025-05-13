<?php

namespace Auth;

use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use GuzzleHttp\Psr7\Response;

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
     *
     * @param ServerRequestInterface $request The request to authenticate
     * @return bool True if authentication is successful, false otherwise
     */
    public function authenticate(ServerRequestInterface $request): bool;

    /**
     * Get the authentication type
     *
     * @return string The authentication type
     */
    public function getType(): string;
}

/**
 * Base class for all authentication methods
 */
abstract class BaseAuth implements AuthenticatorInterface, MiddlewareInterface
{
    /**
     * The authentication type
     *
     * @var string
     */
    protected string $type;

    /**
     * Get the authentication type
     *
     * @return string The authentication type
     */
    public function getType(): string
    {
        return $this->type;
    }

    /**
     * Process the request through the authentication middleware
     *
     * @param ServerRequestInterface $request The request to process
     * @param RequestHandlerInterface $handler The request handler
     * @return ResponseInterface The response
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if (!$this->authenticate($request)) {
            return new Response(401, [], 'Unauthorized');
        }
        return $handler->handle($request);
    }
} 