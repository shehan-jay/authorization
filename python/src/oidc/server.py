from flask import Flask, jsonify, request, redirect, url_for, session
from base_auth import BaseAuth
import jwt
import time
import secrets
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any, Union

class OIDCAuth(BaseAuth):
    """OpenID Connect authentication handler."""
    
    def __init__(self) -> None:
        """Initialize OIDC authentication with test data."""
        super().__init__()
        self.port = 5016
        # In-memory storage for OIDC data (for demonstration)
        self.clients: Dict[str, Dict[str, Any]] = {
            'client123': {
                'client_secret': 'secret123',
                'redirect_uris': ['http://localhost:5016/callback'],
                'grant_types': ['authorization_code', 'refresh_token']
            }
        }
        self.authorization_codes: Dict[str, Tuple[str, str, str, Optional[str]]] = {}  # code -> (client_id, subject, scope, nonce)
        self.access_tokens: Dict[str, Tuple[str, str, str, float]] = {}  # token -> (client_id, subject, scope, expires_at)
        self.refresh_tokens: Dict[str, Tuple[str, str, str]] = {}  # token -> (client_id, subject, scope)
        self.id_tokens: Dict[str, Tuple[str, str, Optional[str], float]] = {}  # token -> (client_id, subject, nonce, expires_at)
        self.users: Dict[str, Dict[str, str]] = {
            'user123': {
                'password': 'password123',
                'name': 'Test User',
                'email': 'test@example.com'
            }
        }

    def authenticate(self, request: Any) -> bool:
        """Authenticate the request using OIDC.
        
        Args:
            request: The request object containing the authorization header.
            
        Returns:
            bool: True if authentication is successful, False otherwise.
        """
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return False

        try:
            # Extract token
            token = auth_header.split(' ')[1]
            
            # Verify token
            if token not in self.access_tokens:
                return False
            
            # Check expiration
            client_id, subject, scope, expires_at = self.access_tokens[token]
            if expires_at < time.time():
                return False
            
            # Store token info in request context
            request.token_info = {
                'client_id': client_id,
                'subject': subject,
                'scope': scope
            }
            return True

        except Exception as e:
            print(f"Authentication error: {str(e)}")
            return False

    def generate_id_token(self, client_id: str, subject: str, nonce: Optional[str] = None) -> str:
        """Generate an ID token.
        
        Args:
            client_id: The client identifier.
            subject: The subject identifier.
            nonce: Optional nonce value for replay protection.
            
        Returns:
            str: The generated ID token.
        """
        token_id = f"_{uuid.uuid4()}"
        expires_at = time.time() + 3600  # 1 hour

        # Create token claims
        claims = {
            'iss': 'http://localhost:5016',
            'sub': subject,
            'aud': client_id,
            'iat': int(time.time()),
            'exp': int(expires_at),
            'jti': token_id
        }
        if nonce:
            claims['nonce'] = nonce

        # Add user info
        user = self.users.get(subject, {})
        claims.update({
            'name': user.get('name'),
            'email': user.get('email')
        })

        # Store token
        self.id_tokens[token_id] = (client_id, subject, nonce, expires_at)

        # Sign token (in a real implementation, use proper signing)
        return jwt.encode(claims, 'secret', algorithm='HS256')

    def generate_access_token(self, client_id: str, subject: str, scope: str) -> str:
        """Generate an access token.
        
        Args:
            client_id: The client identifier.
            subject: The subject identifier.
            scope: The scope of access.
            
        Returns:
            str: The generated access token.
        """
        token_id = f"_{uuid.uuid4()}"
        expires_at = time.time() + 3600  # 1 hour

        # Create token claims
        claims = {
            'iss': 'http://localhost:5016',
            'sub': subject,
            'aud': client_id,
            'iat': int(time.time()),
            'exp': int(expires_at),
            'jti': token_id,
            'scope': scope
        }

        # Store token
        self.access_tokens[token_id] = (client_id, subject, scope, expires_at)

        # Sign token (in a real implementation, use proper signing)
        return jwt.encode(claims, 'secret', algorithm='HS256')

    def generate_refresh_token(self, client_id: str, subject: str, scope: str) -> str:
        """Generate a refresh token.
        
        Args:
            client_id: The client identifier.
            subject: The subject identifier.
            scope: The scope of access.
            
        Returns:
            str: The generated refresh token.
        """
        token_id = f"_{uuid.uuid4()}"

        # Store token
        self.refresh_tokens[token_id] = (client_id, subject, scope)

        # Sign token (in a real implementation, use proper signing)
        return jwt.encode({
            'iss': 'http://localhost:5016',
            'sub': subject,
            'aud': client_id,
            'jti': token_id,
            'scope': scope
        }, 'secret', algorithm='HS256')

    def generate_authorization_code(self, client_id: str, subject: str, scope: str, nonce: Optional[str] = None) -> str:
        """Generate an authorization code.
        
        Args:
            client_id: The client identifier.
            subject: The subject identifier.
            scope: The scope of access.
            nonce: Optional nonce value for replay protection.
            
        Returns:
            str: The generated authorization code.
        """
        code = secrets.token_urlsafe(32)
        self.authorization_codes[code] = (client_id, subject, scope, nonce)
        return code

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
auth = OIDCAuth()

@app.route('/.well-known/openid-configuration', methods=['GET'])
def openid_configuration() -> Dict[str, Any]:
    """OpenID Connect discovery endpoint.
    
    Returns:
        Dict[str, Any]: The OpenID Connect configuration.
    """
    return jsonify({
        'issuer': 'http://localhost:5016',
        'authorization_endpoint': 'http://localhost:5016/authorize',
        'token_endpoint': 'http://localhost:5016/token',
        'userinfo_endpoint': 'http://localhost:5016/userinfo',
        'jwks_uri': 'http://localhost:5016/jwks',
        'response_types_supported': ['code'],
        'subject_types_supported': ['public'],
        'id_token_signing_alg_values_supported': ['HS256'],
        'scopes_supported': ['openid', 'profile', 'email'],
        'token_endpoint_auth_methods_supported': ['client_secret_basic'],
        'claims_supported': ['sub', 'iss', 'name', 'email']
    })

@app.route('/authorize', methods=['GET'])
def authorize() -> Union[Dict[str, str], Tuple[Dict[str, str], int]]:
    """OIDC authorization endpoint.
    
    Returns:
        Union[Dict[str, str], Tuple[Dict[str, str], int]]: The authorization response or error.
    """
    # Get request parameters
    client_id = request.args.get('client_id')
    redirect_uri = request.args.get('redirect_uri')
    response_type = request.args.get('response_type')
    scope = request.args.get('scope', '')
    state = request.args.get('state')
    nonce = request.args.get('nonce')

    # Validate request
    if not all([client_id, redirect_uri, response_type]):
        return jsonify({'error': 'invalid_request'}), 400

    if client_id not in auth.clients:
        return jsonify({'error': 'invalid_client'}), 400

    if redirect_uri not in auth.clients[client_id]['redirect_uris']:
        return jsonify({'error': 'invalid_redirect_uri'}), 400

    if response_type != 'code':
        return jsonify({'error': 'unsupported_response_type'}), 400

    # For demonstration, we'll auto-authenticate the user
    subject = 'user123'
    code = auth.generate_authorization_code(client_id, subject, scope, nonce)

    # Redirect to client with code
    return redirect(f"{redirect_uri}?code={code}&state={state}")

@app.route('/token', methods=['POST'])
def token() -> Union[Dict[str, Any], Tuple[Dict[str, str], int]]:
    """OIDC token endpoint.
    
    Returns:
        Union[Dict[str, Any], Tuple[Dict[str, str], int]]: The token response or error.
    """
    # Get request parameters
    grant_type = request.form.get('grant_type')
    client_id = request.form.get('client_id')
    client_secret = request.form.get('client_secret')
    code = request.form.get('code')
    refresh_token = request.form.get('refresh_token')

    # Validate client
    if client_id not in auth.clients or auth.clients[client_id]['client_secret'] != client_secret:
        return jsonify({'error': 'invalid_client'}), 400

    if grant_type == 'authorization_code':
        # Validate code
        if code not in auth.authorization_codes:
            return jsonify({'error': 'invalid_grant'}), 400

        client_id, subject, scope, nonce = auth.authorization_codes[code]
        del auth.authorization_codes[code]

        # Generate tokens
        access_token = auth.generate_access_token(client_id, subject, scope)
        refresh_token = auth.generate_refresh_token(client_id, subject, scope)
        id_token = auth.generate_id_token(client_id, subject, nonce)

        return jsonify({
            'access_token': access_token,
            'token_type': 'Bearer',
            'expires_in': 3600,
            'refresh_token': refresh_token,
            'id_token': id_token
        })

    elif grant_type == 'refresh_token':
        # Validate refresh token
        if refresh_token not in auth.refresh_tokens:
            return jsonify({'error': 'invalid_grant'}), 400

        client_id, subject, scope = auth.refresh_tokens[refresh_token]

        # Generate new access token
        access_token = auth.generate_access_token(client_id, subject, scope)

        return jsonify({
            'access_token': access_token,
            'token_type': 'Bearer',
            'expires_in': 3600
        })

    else:
        return jsonify({'error': 'unsupported_grant_type'}), 400

@app.route('/userinfo', methods=['GET'])
@auth.requires_auth
def userinfo() -> Dict[str, str]:
    """OIDC userinfo endpoint.
    
    Returns:
        Dict[str, str]: The user information.
    """
    subject = request.token_info['subject']
    user = auth.users.get(subject, {})
    
    return jsonify({
        'sub': subject,
        'name': user.get('name'),
        'email': user.get('email')
    })

@app.route('/jwks', methods=['GET'])
def jwks() -> Dict[str, List[Any]]:
    """JSON Web Key Set endpoint.
    
    Returns:
        Dict[str, List[Any]]: The JSON Web Key Set.
    """
    # In a real implementation, return the public keys
    return jsonify({
        'keys': []
    })

@app.route('/api/secure', methods=['GET', 'POST'])
@auth.requires_auth
def secure_endpoint() -> Dict[str, Any]:
    """Secure endpoint that requires OIDC authentication.
    
    Returns:
        Dict[str, Any]: The secure endpoint response.
    """
    response = {
        'message': 'This is a secure endpoint that requires OIDC authentication',
        'status': 'success',
        'token_info': request.token_info
    }

    if request.method == 'POST':
        response['received_data'] = request.get_json()

    return jsonify(response)

if __name__ == '__main__':
    app.run(debug=True, port=auth.get_port()) 