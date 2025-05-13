# Authentication Methods

This project demonstrates various authentication methods in Go, PHP, Python, and Java. Each authentication method is implemented as a separate module with both server and client components.

## Project Structure

```
.
├── go/
│   └── src/
│       └── auth/
│           ├── base.go
│           ├── no_auth.go
│           ├── basic_auth.go
│           ├── bearer_token.go
│           ├── jwt_bearer.go
│           ├── digest_auth.go
│           ├── oauth1.go
│           ├── oauth2.go
│           ├── hawk_auth.go
│           ├── aws_signature.go
│           ├── ntlm_auth.go
│           ├── api_key.go
│           ├── akamai_edgegrid.go
│           ├── asap_auth.go
│           ├── oidc_auth.go
│           └── saml_auth.go
├── java/
│   └── src/
│       └── main/
│           └── java/
│               └── com/
│                   └── auth/
│                       ├── noauth/
│                       ├── basic/
│                       ├── bearer/
│                       ├── jwt/
│                       ├── digest/
│                       ├── oauth1/
│                       ├── oauth2/
│                       ├── hawk/
│                       ├── aws/
│                       ├── ntlm/
│                       ├── apikey/
│                       ├── akamai/
│                       ├── asap/
│                       ├── oidc/
│                       └── saml/
├── php/
│   └── src/
│       └── Auth/
│           ├── BaseAuth.php
│           ├── NoAuth.php
│           ├── BasicAuth.php
│           ├── BearerToken.php
│           ├── JWTBearer.php
│           ├── DigestAuth.php
│           ├── OAuth1.php
│           ├── OAuth2.php
│           ├── HawkAuth.php
│           ├── AWSSignature.php
│           ├── NTLMAuth.php
│           ├── APIKey.php
│           ├── AkamaiEdgeGrid.php
│           ├── ASAPAuth.php
│           ├── OIDCAuth.php
│           └── SAMLAuth.php
└── python/
    └── src/
        ├── no_auth/
        ├── basic_auth/
        ├── bearer_token/
        ├── jwt_bearer/
        ├── digest_auth/
        ├── oauth1/
        ├── oauth2/
        ├── hawk/
        ├── aws_signature/
        ├── ntlm/
        ├── api_key/
        ├── akamai/
        ├── asap/
        ├── oidc/
        └── saml/
```

## Authentication Methods

1. **No Authentication**
   - Basic endpoint without any authentication
   - Demonstrates the simplest form of API access

2. **Basic Authentication**
   - Username/password based authentication
   - Credentials sent in Base64 encoded format

3. **Bearer Token**
   - Simple token-based authentication
   - Token sent in Authorization header

4. **JWT Bearer**
   - JSON Web Token based authentication
   - Includes token generation and validation

5. **Digest Authentication**
   - Challenge-response authentication
   - More secure than Basic Auth

6. **OAuth 1.0**
   - Three-legged OAuth implementation
   - Includes request signing

7. **OAuth 2.0**
   - Modern OAuth implementation
   - Includes authorization code flow

8. **Hawk Authentication**
   - Message authentication using HMAC
   - Includes request signing

9. **AWS Signature**
   - AWS Signature Version 4
   - Includes request signing and credential scope

10. **NTLM Authentication**
    - Windows authentication protocol
    - Challenge-response mechanism

11. **API Key**
    - Simple API key based authentication
    - Key sent in header or query parameter

12. **Akamai EdgeGrid**
    - Akamai's authentication scheme
    - Includes request signing

13. **ASAP (Atlassian)**
    - Atlassian's authentication scheme
    - JWT-based authentication

## Running the Examples

Each authentication method has its own server and client implementation. To run an example:

1. Start the server:
   ```bash
   # Go
   go run go/src/auth/<auth_method>/server.go

   # Java
   ./mvnw spring-boot:run -pl java

   # PHP
   php -S localhost:8000 -t php/src

   # Python
   python python/src/<auth_method>/server.py
   ```

2. Run the client:
   ```bash
   # Go
   go run go/src/auth/<auth_method>/client.go

   # Java
   ./mvnw exec:java -pl java -Dexec.mainClass="com.auth.<auth_method>.<AuthMethod>Client"

   # PHP
   php php/src/<auth_method>/client.php

   # Python
   python python/src/<auth_method>/client.py
   ```

## Requirements

### Go
- Go 1.16+
- Standard library

### Java
- Java 11+
- Spring Boot
- Spring Security
- JWT
- Apache HttpClient

### PHP
- PHP 8.0+
- Composer
- PSR-7 HTTP Message
- PSR-15 HTTP Server Middleware

### Python
- Python 3.8+
- Flask
- Requests
- PyJWT
- cryptography

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! If you find any issues or bugs, please feel free to open an issue or submit a pull request. Your help in improving this project is greatly appreciated.
