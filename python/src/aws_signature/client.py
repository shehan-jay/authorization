import requests
import hmac
import hashlib
import time
from datetime import datetime
import urllib.parse

class AWSAuth:
    def __init__(self, access_key, secret_key, region='us-east-1', service='example'):
        self.access_key = access_key
        self.secret_key = secret_key
        self.region = region
        self.service = service

    def generate_signature(self, method, path, query_params, headers, body=None):
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
        amz_date = headers['x-amz-date']
        date_stamp = amz_date[:8]
        credential_scope = f"{date_stamp}/{self.region}/{self.service}/aws4_request"
        
        string_to_sign = '\n'.join([
            algorithm,
            amz_date,
            credential_scope,
            hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()
        ])
        
        # Calculate signing key
        def sign(key, msg):
            return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()
        
        k_date = sign(f"AWS4{self.secret_key}".encode('utf-8'), date_stamp)
        k_region = sign(k_date, self.region)
        k_service = sign(k_region, self.service)
        k_signing = sign(k_service, 'aws4_request')
        
        # Calculate signature
        signature = hmac.new(k_signing, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
        
        return signature, credential_scope

    def __call__(self, request):
        # Generate timestamp
        amz_date = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
        date_stamp = amz_date[:8]

        # Add required headers
        request.headers['x-amz-date'] = amz_date
        request.headers['host'] = request.url.hostname

        # Generate signature
        signature, credential_scope = self.generate_signature(
            request.method,
            request.path_url,
            dict(request.params),
            dict(request.headers),
            request.body
        )

        # Create authorization header
        auth_header = (
            f'AWS4-HMAC-SHA256 '
            f'Credential={self.access_key}/{credential_scope}, '
            f'SignedHeaders=host;x-amz-date, '
            f'Signature={signature}'
        )
        request.headers['Authorization'] = auth_header

        return request

class AWSClient:
    def __init__(self, base_url='http://localhost:5008'):
        self.base_url = base_url
        self.access_key = 'AKIAIOSFODNN7EXAMPLE'
        self.secret_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
        self.session = requests.Session()
        self.session.auth = AWSAuth(self.access_key, self.secret_key)

    def call_secure_endpoint(self, method='GET', data=None):
        try:
            url = f"{self.base_url}/api/secure"
            response = self.session.request(
                method=method,
                url=url,
                json=data
            )

            print(f'Status Code: {response.status_code}')
            print(f'Response: {response.json()}')
        except Exception as e:
            print(f"Error: {str(e)}")

if __name__ == '__main__':
    client = AWSClient()
    
    # Test GET request
    print("Testing GET request...")
    client.call_secure_endpoint()
    
    # Test POST request with data
    print("\nTesting POST request...")
    client.call_secure_endpoint(
        method='POST',
        data={'message': 'Hello, AWS!'}
    ) 