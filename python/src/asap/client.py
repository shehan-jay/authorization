import requests
import json
import time
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

class ASAPAuth:
    def __init__(self, issuer, audience, subject, private_key_path=None):
        self.issuer = issuer
        self.audience = audience
        self.subject = subject
        self.private_key = self._load_private_key(private_key_path) if private_key_path else self._generate_private_key()

    def _generate_private_key(self):
        """Generate RSA private key"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    def _load_private_key(self, private_key_path):
        """Load private key from file"""
        with open(private_key_path, 'rb') as key_file:
            return key_file.read()

    def __call__(self, request):
        """Add ASAP authentication to the request"""
        # Generate token
        token = self._generate_token()
        
        # Add authorization header
        request.headers['Authorization'] = f'Bearer {token}'
        return request

    def _generate_token(self, expires_in=3600):
        """Generate ASAP token"""
        now = int(time.time())
        claims = {
            'iss': self.issuer,
            'sub': self.subject,
            'aud': self.audience,
            'iat': now,
            'exp': now + expires_in,
            'jti': f"{now}-{self.subject}"  # Unique token ID
        }

        return jwt.encode(
            claims,
            self.private_key,
            algorithm='RS256'
        )

class ASAPClient:
    def __init__(self, base_url, issuer, audience, subject, private_key_path=None):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.auth = ASAPAuth(issuer, audience, subject, private_key_path)
        self.session.headers.update({
            'Content-Type': 'application/json'
        })

    def generate_token(self, issuer, audience, subject, expires_in=3600):
        """Generate a new ASAP token"""
        response = self.session.post(
            f'{self.base_url}/api/token',
            json={
                'issuer': issuer,
                'audience': audience,
                'subject': subject,
                'expires_in': expires_in
            }
        )
        return response.json()

    def call_secure_endpoint(self, method='GET', data=None):
        """Call the secure endpoint with ASAP authentication"""
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
    client = ASAPClient(
        'http://localhost:5012',
        'service.example.com',
        'api.example.com',
        'test-service'
    )

    # Test GET request
    get_response = client.call_secure_endpoint('GET')
    print('GET Response:', json.dumps(get_response, indent=2))

    # Test POST request
    post_data = {'message': 'Hello from ASAP client!'}
    post_response = client.call_secure_endpoint('POST', post_data)
    print('POST Response:', json.dumps(post_response, indent=2))

if __name__ == '__main__':
    main() 