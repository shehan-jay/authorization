import requests
import hmac
import hashlib
import time
import uuid
import json

class EdgeGridAuth:
    def __init__(self, client_token, client_secret, access_token, host):
        self.client_token = client_token
        self.client_secret = client_secret
        self.access_token = access_token
        self.host = host

    def __call__(self, request):
        """Add EdgeGrid authentication to the request"""
        timestamp = str(int(time.time()))
        nonce = str(uuid.uuid4())

        # Generate signature
        signature = self._generate_signature(
            request.method,
            request.url,
            request.headers,
            request.body,
            timestamp,
            nonce
        )

        # Add authorization header
        auth_header = (
            f'EG1-HMAC-SHA256 client_token={self.client_token};'
            f'access_token={self.access_token};'
            f'timestamp={timestamp};'
            f'nonce={nonce};'
            f'signature={signature}'
        )
        request.headers['Authorization'] = auth_header

        return request

    def _generate_signature(self, method, url, headers, body, timestamp, nonce):
        """Generate EdgeGrid signature"""
        # Parse URL
        from urllib.parse import urlparse, parse_qs
        parsed_url = urlparse(url)
        path = parsed_url.path
        query = '&'.join(f"{k}={v[0]}" for k, v in parse_qs(parsed_url.query).items())

        # Create data to sign
        data_to_sign = [
            method,
            'https',
            self.host,
            path + ('?' + query if query else ''),
            self._get_canonical_headers(headers),
            self._get_content_hash(body),
            self.client_token,
            self.access_token,
            timestamp,
            nonce
        ]
        data_to_sign = '\t'.join(data_to_sign)

        # Create signing key
        signing_key = self._get_signing_key(timestamp)

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

    def _get_signing_key(self, timestamp):
        """Get signing key"""
        date = time.strftime('%Y%m%d', time.gmtime(int(timestamp)))
        key = hmac.new(
            self.client_secret.encode('utf-8'),
            date.encode('utf-8'),
            hashlib.sha256
        ).digest()
        return key

class EdgeGridClient:
    def __init__(self, base_url, client_token, client_secret, access_token, host):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.auth = EdgeGridAuth(client_token, client_secret, access_token, host)
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Host': host
        })

    def call_secure_endpoint(self, method='GET', data=None):
        """Call the secure endpoint with EdgeGrid authentication"""
        if method.upper() == 'GET':
            response = self.session.get(f'{self.base_url}/api/secure')
        else:
            response = self.session.post(
                f'{self.base_url}/api/secure',
                json=data
            )
        return response.json()

def main():
    # Example usage
    client = EdgeGridClient(
        'http://localhost:5011',
        'client_token',
        'client_secret_123',
        'access_token_123',
        'akab-xxxxx.luna.akamaiapis.net'
    )

    # Test GET request
    get_response = client.call_secure_endpoint('GET')
    print('GET Response:', json.dumps(get_response, indent=2))

    # Test POST request
    post_data = {'message': 'Hello from EdgeGrid client!'}
    post_response = client.call_secure_endpoint('POST', post_data)
    print('POST Response:', json.dumps(post_response, indent=2))

if __name__ == '__main__':
    main() 