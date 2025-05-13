# Authentication Methods Demo

This project demonstrates various authentication methods in both Python and Java. Each authentication method is implemented as a separate module with both server and client components.

## Project Structure

```
.
├── python/
│   └── src/
│       ├── no_auth/
│       ├── basic_auth/
│       ├── bearer_token/
│       ├── jwt_bearer/
│       ├── digest_auth/
│       ├── oauth1/
│       ├── oauth2/
│       ├── hawk/
│       ├── aws_signature/
│       ├── ntlm/
│       ├── api_key/
│       ├── akamai/
│       └── asap/
└── java/
    └── src/
        └── main/
            └── java/
                └── com/
                    └── auth/
                        ├── noauth/
                        ├── basic/
                        ├── bearer/
                        ├── jwt/
                        ├── digest/
                        ├── oauth1/
                        ├── oauth2/
                        ├── hawk/
                        ├── aws/
                        ├── ntlm/
                        ├── apikey/
                        ├── akamai/
                        └── asap/
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
   # Python
   python python/src/<auth_method>/server.py

   # Java
   ./mvnw spring-boot:run -pl java
   ```

2. Run the client:
   ```bash
   # Python
   python python/src/<auth_method>/client.py

   # Java
   ./mvnw exec:java -pl java -Dexec.mainClass="com.auth.<auth_method>.<AuthMethod>Client"
   ```

## Requirements

### Python
- Python 3.8+
- Flask
- Requests
- PyJWT
- cryptography

### Java
- Java 11+
- Spring Boot
- Spring Security
- JWT
- Apache HttpClient

## License

This project is licensed under the MIT License - see the LICENSE file for details.
