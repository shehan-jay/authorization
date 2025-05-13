from flask import Flask, jsonify, request
from base_auth import BaseAuth
import hmac
import hashlib
import base64
import time
import re

class EdgeGridAuth(BaseAuth):
    def __init__(self):
        super().__init__()
        self.port = 5011
        # In-memory storage for EdgeGrid credentials (for demonstration)
        self.credentials = {
            'client_token': {
                'client_secret': 'client_secret_123',
                'access_token': 'access_token_123',
                'host': 'akab-xxxxx.luna.akamaiapis.net'
            }
        }

    def authenticate(self, request):
        """Authenticate the request using Akamai EdgeGrid"""
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('EG1-HMAC-SHA256'):
            return False

        # Parse the authorization header
        try:
            # Format: EG1-HMAC-SHA256 client_token=xxx;access_token=xxx;timestamp=xxx;nonce=xxx;signature=xxx
            auth_parts = dict(item.split("=") for item in auth_header.split('EG1-HMAC-SHA256 ')[1].split(';'))
            
            client_token = auth_parts.get('client_token')
            access_token = auth_parts.get('access_token')
            timestamp = auth_parts.get('timestamp')
            nonce = auth_parts.get('nonce')
            signature = auth_parts.get('signature')

            if not all([client_token, access_token, timestamp, nonce, signature]):
                return False

            # Verify timestamp is within 5 minutes
            if abs(int(time.time()) - int(timestamp)) > 300:
                return False

            # Get client secret
            if client_token not in self.credentials:
                return False
            client_secret = self.credentials[client_token]['client_secret']

            # Generate expected signature
            expected_signature = self._generate_signature(
                request.method,
                request.path,
                request.query_string.decode() if request.query_string else '',
                request.headers,
                request.get_data(),
                client_token,
                access_token,
                timestamp,
                nonce,
                client_secret
            )

            # Compare signatures
            if not hmac.compare_digest(signature, expected_signature):
                return False

            # Store client info in request context
            request.client_token = client_token
            request.access_token = access_token
            
            return True

        except Exception as e:
            print(f"Authentication error: {str(e)}")
            return False

    def _generate_signature(self, method, path, query, headers, body, client_token, access_token, timestamp, nonce, client_secret):
        """Generate EdgeGrid signature"""
        # Create data to sign
        data_to_sign = [
            method,
            'https',
            headers.get('Host', ''),
            path + ('?' + query if query else ''),
            self._get_canonical_headers(headers),
            self._get_content_hash(body),
            client_token,
            access_token,
            timestamp,
            nonce
        ]
        data_to_sign = '\t'.join(data_to_sign)

        # Create signing key
        signing_key = self._get_signing_key(client_secret, timestamp)

        # Generate signature
        signature = hmac.new(
            signing_key,
            data_to_sign.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

        return signature

    def _get_canonical_headers(self, headers):
        """Get canonical headers string"""
        canonical_headers = []
        for header in sorted(headers.keys()):
            if header.lower() in ['content-type', 'host']:
                canonical_headers.append(f"{header.lower()}:{headers[header]}")
        return '\t'.join(canonical_headers)

    def _get_content_hash(self, body):
        """Get content hash"""
        if not body:
            return hashlib.sha256(b'').hexdigest()
        return hashlib.sha256(body).hexdigest()

    def _get_signing_key(self, client_secret, timestamp):
        """Get signing key"""
        date = time.strftime('%Y%m%d', time.gmtime(int(timestamp)))
        key = hmac.new(
            client_secret.encode('utf-8'),
            date.encode('utf-8'),
            hashlib.sha256
        ).digest()
        return key

app = Flask(__name__)
auth = EdgeGridAuth()

@app.route('/api/secure', methods=['GET', 'POST'])
@auth.requires_auth
def secure_endpoint():
    """Secure endpoint that requires EdgeGrid authentication"""
    response = {
        'message': 'This is a secure endpoint that requires Akamai EdgeGrid authentication',
        'status': 'success',
        'client_token': request.client_token,
        'access_token': request.access_token
    }

    if request.method == 'POST':
        response['received_data'] = request.get_json()

    return jsonify(response)

if __name__ == '__main__':
    app.run(debug=True, port=auth.get_port()) 