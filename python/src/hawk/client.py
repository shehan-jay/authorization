import requests
import hmac
import hashlib
import time
import base64
import secrets
import json

class HawkAuth:
    def __init__(self, hawk_id, hawk_key, algorithm='sha256'):
        self.hawk_id = hawk_id
        self.hawk_key = hawk_key
        self.algorithm = algorithm

    def generate_mac(self, timestamp, nonce, method, uri, host, port, payload_hash=None):
        # Create normalized string
        normalized = f"hawk.1.header\n{timestamp}\n{nonce}\n{method}\n{uri}\n{host}\n{port}\n{payload_hash or ''}\n\n"
        
        # Calculate MAC
        mac = hmac.new(
            self.hawk_key.encode('utf-8'),
            normalized.encode('utf-8'),
            getattr(hashlib, self.algorithm)
        ).digest()
        
        return base64.b64encode(mac).decode('utf-8')

    def __call__(self, request):
        # Generate timestamp and nonce
        timestamp = str(int(time.time()))
        nonce = secrets.token_hex(8)

        # Calculate payload hash if present
        payload_hash = None
        if request.body:
            payload_hash = base64.b64encode(
                hashlib.sha256(request.body).digest()
            ).decode('utf-8')

        # Generate MAC
        mac = self.generate_mac(
            timestamp,
            nonce,
            request.method,
            request.path_url,
            request.url.hostname,
            str(request.url.port or 80),
            payload_hash
        )

        # Create Hawk header
        hawk_header = (
            f'Hawk id="{self.hawk_id}", '
            f'ts="{timestamp}", '
            f'nonce="{nonce}", '
            f'mac="{mac}"'
        )
        if payload_hash:
            hawk_header += f', hash="{payload_hash}"'

        request.headers['Authorization'] = hawk_header
        return request

class HawkClient:
    def __init__(self, base_url='http://localhost:5007'):
        self.base_url = base_url
        self.hawk_id = 'hawk_id_1'
        self.hawk_key = 'hawk_key_1'
        self.session = requests.Session()
        self.session.auth = HawkAuth(self.hawk_id, self.hawk_key)

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
    client = HawkClient()
    
    # Test GET request
    print("Testing GET request...")
    client.call_secure_endpoint()
    
    # Test POST request with data
    print("\nTesting POST request...")
    client.call_secure_endpoint(
        method='POST',
        data={'message': 'Hello, Hawk!'}
    ) 