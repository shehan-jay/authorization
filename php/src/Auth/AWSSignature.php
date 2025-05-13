<?php

namespace Auth;

use Psr\Http\Message\ServerRequestInterface;

class AWSSignature extends BaseAuth
{
    private string $accessKey;
    private string $secretKey;
    private string $region;
    private string $service;

    public function __construct(string $accessKey, string $secretKey, string $region, string $service)
    {
        $this->type = AuthType::AWS;
        $this->accessKey = $accessKey;
        $this->secretKey = $secretKey;
        $this->region = $region;
        $this->service = $service;
    }

    public function authenticate(ServerRequestInterface $request): bool
    {
        // TODO: Implement AWS Signature validation
        return true;
    }

    public function addAuth(ServerRequestInterface $request): ServerRequestInterface
    {
        // TODO: Add Authorization header
        return $request;
    }
} 