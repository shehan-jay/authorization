from flask import Flask, jsonify, request
from base_auth import BaseAuth
import jwt
import time
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

class ASAPAuth(BaseAuth):
    def __init__(self):
        super().__init__()
        self.port = 5012
        # In-memory storage for ASAP credentials (for demonstration)
        self.credentials = {
            'issuer': {
                'public_key': self._generate_key_pair(),
                'audience': 'api.example.com',
                'issuer': 'service.example.com'
            }
        }

    def _generate_key_pair(self):
        """Generate RSA key pair for ASAP"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        # Store private key for token generation
        self.private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Return public key for verification
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def authenticate(self, request):
        """Authenticate the request using ASAP"""
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return False

        try:
            # Extract token
            token = auth_header.split(' ')[1]
            
            # Get issuer from token
            unverified_claims = jwt.decode(token, options={"verify_signature": False})
            issuer = unverified_claims.get('iss')
            
            if issuer not in self.credentials:
                return False
            
            # Verify token
            public_key = self.credentials[issuer]['public_key']
            claims = jwt.decode(
                token,
                public_key,
                algorithms=['RS256'],
                audience=self.credentials[issuer]['audience'],
                issuer=issuer
            )
            
            # Store claims in request context
            request.claims = claims
            return True

        except Exception as e:
            print(f"Authentication error: {str(e)}")
            return False

    def generate_token(self, issuer, audience, subject, expires_in=3600):
        """Generate ASAP token"""
        if issuer not in self.credentials:
            raise ValueError("Unknown issuer")

        now = int(time.time())
        claims = {
            'iss': issuer,
            'sub': subject,
            'aud': audience,
            'iat': now,
            'exp': now + expires_in,
            'jti': f"{now}-{subject}"  # Unique token ID
        }

        return jwt.encode(
            claims,
            self.private_key,
            algorithm='RS256'
        )

app = Flask(__name__)
auth = ASAPAuth()

@app.route('/api/token', methods=['POST'])
def generate_token():
    """Endpoint to generate ASAP token"""
    try:
        data = request.get_json()
        issuer = data.get('issuer')
        audience = data.get('audience')
        subject = data.get('subject')
        expires_in = data.get('expires_in', 3600)

        if not all([issuer, audience, subject]):
            return jsonify({'error': 'Missing required fields'}), 400

        token = auth.generate_token(issuer, audience, subject, expires_in)
        return jsonify({'token': token})

    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/secure', methods=['GET', 'POST'])
@auth.requires_auth
def secure_endpoint():
    """Secure endpoint that requires ASAP authentication"""
    response = {
        'message': 'This is a secure endpoint that requires ASAP authentication',
        'status': 'success',
        'claims': request.claims
    }

    if request.method == 'POST':
        response['received_data'] = request.get_json()

    return jsonify(response)

if __name__ == '__main__':
    app.run(debug=True, port=auth.get_port()) 