import requests
from requests.auth import HTTPDigestAuth
import hashlib
import time
import random
import string

class DigestAuthClient:
    def __init__(self, base_url='http://localhost:5004'):
        self.base_url = base_url
        self.username = 'admin'
        self.password = 'password123'

    def generate_cnonce(self):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=32))

    def call_secure_endpoint(self):
        try:
            # First request will get a 401 with WWW-Authenticate header
            response = requests.get(f'{self.base_url}/api/secure')
            
            if response.status_code == 401:
                auth_header = response.headers.get('WWW-Authenticate')
                if not auth_header or not auth_header.startswith('Digest '):
                    print("Server did not return proper digest authentication challenge")
                    return

                # Parse digest parameters
                auth_params = dict(param.split('=', 1) for param in auth_header[7:].split(', '))
                auth_params = {k: v.strip('"') for k, v in auth_params.items()}
                
                realm = auth_params.get('realm')
                nonce = auth_params.get('nonce')
                qop = auth_params.get('qop')
                
                # Generate client nonce and nonce count
                cnonce = self.generate_cnonce()
                nc = '00000001'
                
                # Calculate digest
                ha1 = hashlib.md5(f"{self.username}:{realm}:{self.password}".encode()).hexdigest()
                ha2 = hashlib.md5(f"GET:/api/secure".encode()).hexdigest()
                response = hashlib.md5(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}".encode()).hexdigest()
                
                # Construct Authorization header
                auth_header = (
                    f'Digest username="{self.username}", '
                    f'realm="{realm}", '
                    f'nonce="{nonce}", '
                    f'uri="/api/secure", '
                    f'algorithm=MD5, '
                    f'qop={qop}, '
                    f'nc={nc}, '
                    f'cnonce="{cnonce}", '
                    f'response="{response}"'
                )
                
                # Make authenticated request
                headers = {'Authorization': auth_header}
                response = requests.get(f'{self.base_url}/api/secure', headers=headers)
            
            print(f'Status Code: {response.status_code}')
            print(f'Response: {response.json()}')
            
        except requests.exceptions.RequestException as e:
            print(f'Error: {e}')

if __name__ == '__main__':
    client = DigestAuthClient()
    
    # Test with valid credentials
    print("Testing with valid credentials:")
    client.call_secure_endpoint()
    
    # Test with invalid credentials
    print("\nTesting with invalid credentials:")
    client.password = "wrongpassword"
    client.call_secure_endpoint() 