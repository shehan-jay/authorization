from flask import Flask, jsonify, request, redirect, url_for
from base_auth import BaseAuth
import jwt
import time
import json
import secrets
from datetime import datetime, timedelta

class OAuth2Auth(BaseAuth):
    def __init__(self):
        super().__init__()
        self.port = 5013
        # In-memory storage for OAuth 2.0 data (for demonstration)
        self.clients = {
            'client_id': {
                'client_secret': 'client_secret_123',
                'redirect_uris': ['http://localhost:5013/callback'],
                'grant_types': ['authorization_code', 'refresh_token']
            }
        }
        self.authorization_codes = {}  # code -> (client_id, user_id, scope, expires_at)
        self.access_tokens = {}  # token -> (client_id, user_id, scope, expires_at)
        self.refresh_tokens = {}  # token -> (client_id, user_id, scope)
        self.jwt_secret = secrets.token_hex(32)

    def authenticate(self, request):
        """Authenticate the request using OAuth 2.0"""
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return False

        try:
            # Extract token
            token = auth_header.split(' ')[1]
            
            # Verify token
            payload = jwt.decode(token, self.jwt_secret, algorithms=['HS256'])
            
            # Check if token is expired
            if payload['exp'] < time.time():
                return False
            
            # Store token info in request context
            request.token_info = payload
            return True

        except Exception as e:
            print(f"Authentication error: {str(e)}")
            return False

    def generate_access_token(self, client_id, user_id, scope):
        """Generate OAuth 2.0 access token"""
        expires_at = time.time() + 3600  # 1 hour
        token = jwt.encode(
            {
                'client_id': client_id,
                'user_id': user_id,
                'scope': scope,
                'exp': expires_at
            },
            self.jwt_secret,
            algorithm='HS256'
        )
        self.access_tokens[token] = (client_id, user_id, scope, expires_at)
        return token

    def generate_refresh_token(self, client_id, user_id, scope):
        """Generate OAuth 2.0 refresh token"""
        token = secrets.token_urlsafe(32)
        self.refresh_tokens[token] = (client_id, user_id, scope)
        return token

    def generate_authorization_code(self, client_id, user_id, scope):
        """Generate OAuth 2.0 authorization code"""
        code = secrets.token_urlsafe(32)
        expires_at = time.time() + 600  # 10 minutes
        self.authorization_codes[code] = (client_id, user_id, scope, expires_at)
        return code

app = Flask(__name__)
auth = OAuth2Auth()

@app.route('/oauth/authorize', methods=['GET'])
def authorize():
    """OAuth 2.0 authorization endpoint"""
    client_id = request.args.get('client_id')
    redirect_uri = request.args.get('redirect_uri')
    response_type = request.args.get('response_type')
    scope = request.args.get('scope', '')
    state = request.args.get('state')

    # Validate client
    if client_id not in auth.clients:
        return jsonify({'error': 'invalid_client'}), 400

    # Validate redirect URI
    if redirect_uri not in auth.clients[client_id]['redirect_uris']:
        return jsonify({'error': 'invalid_redirect_uri'}), 400

    # For demonstration, we'll auto-approve the request
    if response_type == 'code':
        code = auth.generate_authorization_code(client_id, 'user123', scope)
        return redirect(f"{redirect_uri}?code={code}&state={state}")
    else:
        return jsonify({'error': 'unsupported_response_type'}), 400

@app.route('/oauth/token', methods=['POST'])
def token():
    """OAuth 2.0 token endpoint"""
    grant_type = request.form.get('grant_type')
    client_id = request.form.get('client_id')
    client_secret = request.form.get('client_secret')

    # Validate client credentials
    if client_id not in auth.clients or auth.clients[client_id]['client_secret'] != client_secret:
        return jsonify({'error': 'invalid_client'}), 401

    if grant_type == 'authorization_code':
        code = request.form.get('code')
        if code not in auth.authorization_codes:
            return jsonify({'error': 'invalid_grant'}), 400

        client_id, user_id, scope, expires_at = auth.authorization_codes[code]
        if expires_at < time.time():
            return jsonify({'error': 'invalid_grant'}), 400

        # Generate tokens
        access_token = auth.generate_access_token(client_id, user_id, scope)
        refresh_token = auth.generate_refresh_token(client_id, user_id, scope)

        # Remove used authorization code
        del auth.authorization_codes[code]

        return jsonify({
            'access_token': access_token,
            'token_type': 'Bearer',
            'expires_in': 3600,
            'refresh_token': refresh_token,
            'scope': scope
        })

    elif grant_type == 'refresh_token':
        refresh_token = request.form.get('refresh_token')
        if refresh_token not in auth.refresh_tokens:
            return jsonify({'error': 'invalid_grant'}), 400

        client_id, user_id, scope = auth.refresh_tokens[refresh_token]
        access_token = auth.generate_access_token(client_id, user_id, scope)

        return jsonify({
            'access_token': access_token,
            'token_type': 'Bearer',
            'expires_in': 3600,
            'scope': scope
        })

    else:
        return jsonify({'error': 'unsupported_grant_type'}), 400

@app.route('/api/secure', methods=['GET', 'POST'])
@auth.requires_auth
def secure_endpoint():
    """Secure endpoint that requires OAuth 2.0 authentication"""
    response = {
        'message': 'This is a secure endpoint that requires OAuth 2.0 authentication',
        'status': 'success',
        'token_info': request.token_info
    }

    if request.method == 'POST':
        response['received_data'] = request.get_json()

    return jsonify(response)

if __name__ == '__main__':
    app.run(debug=True, port=auth.get_port()) 