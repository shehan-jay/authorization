import requests
import json
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
import threading

class OAuth2Client:
    def __init__(self, client_id, client_secret, redirect_uri, auth_url, token_url):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.auth_url = auth_url
        self.token_url = token_url
        self.access_token = None
        self.refresh_token = None
        self.token_type = None
        self.expires_in = None
        self.scope = None

    def start_authorization(self, scope=''):
        """Start OAuth 2.0 authorization flow"""
        # Start local server to receive callback
        server = self._start_callback_server()
        
        # Open browser for authorization
        auth_params = {
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'response_type': 'code',
            'scope': scope,
            'state': 'state123'  # In production, use a random state
        }
        auth_url = f"{self.auth_url}?{'&'.join(f'{k}={v}' for k, v in auth_params.items())}"
        webbrowser.open(auth_url)

        # Wait for callback
        server.serve_forever()

    def _start_callback_server(self):
        """Start local server to receive OAuth callback"""
        class CallbackHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                # Parse callback URL
                query = parse_qs(urlparse(self.path).query)
                code = query.get('code', [None])[0]
                state = query.get('state', [None])[0]

                if code:
                    # Exchange code for tokens
                    self.server.oauth_client.exchange_code(code)
                    
                    # Send success response
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    self.wfile.write(b"Authorization successful! You can close this window.")
                else:
                    # Send error response
                    self.send_response(400)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    self.wfile.write(b"Authorization failed!")

                # Stop server
                threading.Thread(target=self.server.shutdown).start()

        # Create server
        server = HTTPServer(('localhost', 5013), CallbackHandler)
        server.oauth_client = self
        return server

    def exchange_code(self, code):
        """Exchange authorization code for tokens"""
        data = {
            'grant_type': 'authorization_code',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code': code,
            'redirect_uri': self.redirect_uri
        }
        response = requests.post(self.token_url, data=data)
        self._handle_token_response(response)

    def refresh_access_token(self):
        """Refresh access token using refresh token"""
        if not self.refresh_token:
            raise ValueError("No refresh token available")

        data = {
            'grant_type': 'refresh_token',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'refresh_token': self.refresh_token
        }
        response = requests.post(self.token_url, data=data)
        self._handle_token_response(response)

    def _handle_token_response(self, response):
        """Handle token response"""
        if response.status_code != 200:
            raise Exception(f"Token request failed: {response.text}")

        token_data = response.json()
        self.access_token = token_data['access_token']
        self.token_type = token_data['token_type']
        self.expires_in = token_data['expires_in']
        self.scope = token_data.get('scope')
        self.refresh_token = token_data.get('refresh_token')

    def call_secure_endpoint(self, url, method='GET', data=None):
        """Call secure endpoint with OAuth 2.0 authentication"""
        if not self.access_token:
            raise ValueError("No access token available")

        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }

        if method.upper() == 'GET':
            response = requests.get(url, headers=headers)
        else:
            response = requests.post(url, headers=headers, json=data)

        if response.status_code == 401 and self.refresh_token:
            # Token expired, try to refresh
            self.refresh_access_token()
            return self.call_secure_endpoint(url, method, data)

        return response.json()

def main():
    # Example usage
    client = OAuth2Client(
        client_id='client_id',
        client_secret='client_secret_123',
        redirect_uri='http://localhost:5013/callback',
        auth_url='http://localhost:5013/oauth/authorize',
        token_url='http://localhost:5013/oauth/token'
    )

    # Start authorization flow
    client.start_authorization(scope='read write')

    # Test secure endpoint
    response = client.call_secure_endpoint('http://localhost:5013/api/secure')
    print('GET Response:', json.dumps(response, indent=2))

    # Test POST request
    post_data = {'message': 'Hello from OAuth 2.0 client!'}
    response = client.call_secure_endpoint(
        'http://localhost:5013/api/secure',
        method='POST',
        data=post_data
    )
    print('POST Response:', json.dumps(response, indent=2))

if __name__ == '__main__':
    main() 