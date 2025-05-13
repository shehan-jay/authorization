import requests
import json
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
import threading
import jwt
import time
import secrets
from typing import Dict, List, Optional, Any, Union, Tuple

class OIDCClient:
    """OpenID Connect client for authentication."""
    
    def __init__(self, client_id: str, client_secret: str, redirect_uri: str, issuer_url: str) -> None:
        """Initialize OIDC client.
        
        Args:
            client_id: The client identifier.
            client_secret: The client secret.
            redirect_uri: The redirect URI for callbacks.
            issuer_url: The OpenID Connect issuer URL.
        """
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.issuer_url = issuer_url
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None
        self.id_token: Optional[str] = None
        self.token_expires_at: Optional[float] = None
        self.user_info: Optional[Dict[str, Any]] = None
        self._load_configuration()

    def _load_configuration(self) -> None:
        """Load OpenID Connect configuration."""
        response = requests.get(f"{self.issuer_url}/.well-known/openid-configuration")
        self.config = response.json()

    def start_authentication(self, scope: str = 'openid profile email') -> None:
        """Start OIDC authentication flow.
        
        Args:
            scope: The scope of access.
        """
        # Generate state and nonce
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)

        # Start local server to receive callback
        server = self._start_callback_server()

        # Build authorization URL
        auth_url = f"{self.config['authorization_endpoint']}?" + "&".join([
            f"client_id={self.client_id}",
            f"redirect_uri={self.redirect_uri}",
            "response_type=code",
            f"scope={scope}",
            f"state={state}",
            f"nonce={nonce}"
        ])

        # Open browser for authentication
        webbrowser.open(auth_url)

        # Wait for callback
        server.serve_forever()

    def _start_callback_server(self) -> HTTPServer:
        """Start local server to receive OIDC callback.
        
        Returns:
            HTTPServer: The callback server.
        """
        class CallbackHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                # Parse callback URL
                query = urlparse(self.path).query
                params = parse_qs(query)

                code = params.get('code', [None])[0]
                state = params.get('state', [None])[0]

                if code:
                    # Process authorization code
                    self.server.oidc_client._handle_authorization_code(code)
                    
                    # Send success response
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    self.wfile.write(b"Authentication successful! You can close this window.")
                else:
                    # Send error response
                    self.send_response(400)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    self.wfile.write(b"Authentication failed!")

                # Stop server
                threading.Thread(target=self.server.shutdown).start()

        # Create server
        server = HTTPServer(('localhost', 5016), CallbackHandler)
        server.oidc_client = self
        return server

    def _handle_authorization_code(self, code: str) -> None:
        """Exchange authorization code for tokens.
        
        Args:
            code: The authorization code.
        """
        # Request tokens
        response = requests.post(
            self.config['token_endpoint'],
            data={
                'grant_type': 'authorization_code',
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'code': code,
                'redirect_uri': self.redirect_uri
            }
        )

        if response.status_code != 200:
            raise Exception(f"Token request failed: {response.text}")

        # Parse response
        token_data = response.json()
        self.access_token = token_data['access_token']
        self.refresh_token = token_data.get('refresh_token')
        self.id_token = token_data.get('id_token')
        self.token_expires_at = time.time() + token_data['expires_in']

        # Verify ID token
        if self.id_token:
            self._verify_id_token()

        # Get user info
        self._get_user_info()

    def _verify_id_token(self) -> None:
        """Verify ID token."""
        try:
            # Decode token (in a real implementation, verify signature)
            claims = jwt.decode(self.id_token, options={"verify_signature": False})
            
            # Verify claims
            if claims['iss'] != self.issuer_url:
                raise Exception("Invalid issuer")
            if claims['aud'] != self.client_id:
                raise Exception("Invalid audience")
            if claims['exp'] < time.time():
                raise Exception("Token expired")

        except Exception as e:
            print(f"ID token verification failed: {str(e)}")
            raise

    def _get_user_info(self) -> None:
        """Get user info."""
        response = requests.get(
            self.config['userinfo_endpoint'],
            headers={'Authorization': f'Bearer {self.access_token}'}
        )

        if response.status_code != 200:
            raise Exception(f"User info request failed: {response.text}")

        self.user_info = response.json()

    def _refresh_access_token(self) -> None:
        """Refresh access token."""
        if not self.refresh_token:
            raise Exception("No refresh token available")

        response = requests.post(
            self.config['token_endpoint'],
            data={
                'grant_type': 'refresh_token',
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'refresh_token': self.refresh_token
            }
        )

        if response.status_code != 200:
            raise Exception(f"Token refresh failed: {response.text}")

        # Update tokens
        token_data = response.json()
        self.access_token = token_data['access_token']
        self.token_expires_at = time.time() + token_data['expires_in']

    def call_secure_endpoint(self, url: str, method: str = 'GET', data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Call secure endpoint with OIDC authentication.
        
        Args:
            url: The endpoint URL.
            method: The HTTP method.
            data: Optional request data.
            
        Returns:
            Dict[str, Any]: The endpoint response.
        """
        if not self.access_token:
            raise ValueError("Not authenticated. Call start_authentication() first.")

        # Check if token needs refresh
        if self.token_expires_at and time.time() >= self.token_expires_at:
            self._refresh_access_token()

        # Make request
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }

        if method.upper() == 'GET':
            response = requests.get(url, headers=headers)
        else:
            response = requests.post(url, headers=headers, json=data)

        return response.json()

def main() -> None:
    """Example usage of OIDC client."""
    # Create OIDC client
    client = OIDCClient(
        client_id='client123',
        client_secret='secret123',
        redirect_uri='http://localhost:5016/callback',
        issuer_url='http://localhost:5016'
    )

    # Start authentication flow
    client.start_authentication()

    # Test secure endpoint
    response = client.call_secure_endpoint('http://localhost:5016/api/secure')
    print('GET Response:', json.dumps(response, indent=2))

    # Test POST request
    post_data = {'message': 'Hello from OIDC client!'}
    response = client.call_secure_endpoint(
        'http://localhost:5016/api/secure',
        method='POST',
        data=post_data
    )
    print('POST Response:', json.dumps(response, indent=2))

if __name__ == '__main__':
    main() 