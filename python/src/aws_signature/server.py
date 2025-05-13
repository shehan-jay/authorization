from flask import Flask, jsonify, request
from base_auth import BaseAuth
import hmac
import hashlib
import time
import base64
import json
from datetime import datetime
import urllib.parse

class AWSAuth(BaseAuth):
    def __init__(self):
        super().__init__()
        self.port = 5008
        # In-memory storage for AWS credentials (for demonstration)
        self.credentials = {
            'AKIAIOSFODNN7EXAMPLE': {
                'secret_key': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
                'region': 'us-east-1',
                'service': 'example'
            }
        }

    def generate_signature(self, credentials, method, path, query_params, headers, body=None):
        # Create canonical request
        canonical_headers = '\n'.join(f"{k.lower()}:{v.strip()}" for k, v in sorted(headers.items()))
        signed_headers = ';'.join(k.lower() for k in sorted(headers.keys()))
        
        # Create payload hash
        payload_hash = hashlib.sha256(body.encode('utf-8') if body else b'').hexdigest()
        
        # Create canonical request string
        canonical_request = '\n'.join([
            method,
            path,
            urllib.parse.urlencode(sorted(query_params.items())) if query_params else '',
            canonical_headers,
            signed_headers,
            payload_hash
        ])
        
        # Create string to sign
        algorithm = 'AWS4-HMAC-SHA256'
        amz_date = headers.get('x-amz-date', '')
        date_stamp = amz_date[:8]
        credential_scope = f"{date_stamp}/{credentials['region']}/{credentials['service']}/aws4_request"
        
        string_to_sign = '\n'.join([
            algorithm,
            amz_date,
            credential_scope,
            hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()
        ])
        
        # Calculate signing key
        def sign(key, msg):
            return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()
        
        k_date = sign(f"AWS4{credentials['secret_key']}".encode('utf-8'), date_stamp)
        k_region = sign(k_date, credentials['region'])
        k_service = sign(k_region, credentials['service'])
        k_signing = sign(k_service, 'aws4_request')
        
        # Calculate signature
        signature = hmac.new(k_signing, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
        
        return signature

    def authenticate(self, request):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('AWS4-HMAC-SHA256'):
            return False

        try:
            # Parse authorization header
            auth_parts = auth_header.split(', ')
            auth_dict = dict(part.split('=', 1) for part in auth_parts)
            
            # Extract credentials
            access_key = auth_dict.get('Credential').split('/')[0]
            if access_key not in self.credentials:
                return False
            
            credentials = self.credentials[access_key]
            
            # Get request details
            method = request.method
            path = request.path
            query_params = dict(request.args)
            headers = dict(request.headers)
            body = request.get_data(as_text=True)
            
            # Generate expected signature
            expected_signature = self.generate_signature(
                credentials,
                method,
                path,
                query_params,
                headers,
                body
            )
            
            # Verify signature
            return auth_dict.get('Signature') == expected_signature
        except Exception:
            return False

app = Flask(__name__)
auth = AWSAuth()

@app.route('/api/secure', methods=['GET', 'POST'])
@auth.requires_auth
def secure_endpoint():
    return jsonify({
        'message': 'This is a secure endpoint that requires AWS Signature authentication',
        'status': 'success'
    })

if __name__ == '__main__':
    app.run(debug=True, port=auth.get_port()) 