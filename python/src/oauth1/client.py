import requests
import time
import secrets
import hashlib
import hmac
import base64
import urllib.parse

class OAuth1Client:
    def __init__(self, base_url='http://localhost:5005'):
        self.base_url = base_url
        self.consumer_key = 'consumer_key_1'
        self.consumer_secret = 'consumer_secret_1'
        self.request_token = None
        self.request_token_secret = None
        self.access_token = None
        self.access_token_secret = None

    def generate_nonce(self):
        return secrets.token_urlsafe(16)

    def generate_signature(self, method, url, params, token_secret=None):
        # Sort parameters
        sorted_params = sorted(params.items())
        param_string = '&'.join(f'{k}={urllib.parse.quote(str(v), safe="")}' for k, v in sorted_params)
        
        # Create signature base string
        base_string = f'{method.upper()}&{urllib.parse.quote(url, safe="")}&{urllib.parse.quote(param_string, safe="")}'
        
        # Create signing key
        signing_key = f'{urllib.parse.quote(self.consumer_secret, safe="")}&'
        if token_secret:
            signing_key += urllib.parse.quote(token_secret, safe="")
        
        # Generate signature
        signature = hmac.new(
            signing_key.encode('utf-8'),
            base_string.encode('utf-8'),
            hashlib.sha1
        ).digest()
        
        return base64.b64encode(signature).decode('utf-8')

    def get_request_token(self):
        params = {
            'oauth_consumer_key': self.consumer_key,
            'oauth_nonce': self.generate_nonce(),
            'oauth_signature_method': 'HMAC-SHA1',
            'oauth_timestamp': str(int(time.time())),
            'oauth_version': '1.0'
        }
        
        # Generate signature
        params['oauth_signature'] = self.generate_signature('POST', f'{self.base_url}/oauth/request_token', params)
        
        # Make request
        response = requests.post(
            f'{self.base_url}/oauth/request_token',
            data=params
        )
        
        if response.status_code == 200:
            data = response.json()
            self.request_token = data['oauth_token']
            self.request_token_secret = data['oauth_token_secret']
            return True
        return False

    def get_access_token(self):
        if not self.request_token:
            print("Request token not obtained")
            return False

        params = {
            'oauth_consumer_key': self.consumer_key,
            'oauth_nonce': self.generate_nonce(),
            'oauth_signature_method': 'HMAC-SHA1',
            'oauth_timestamp': str(int(time.time())),
            'oauth_token': self.request_token,
            'oauth_version': '1.0'
        }
        
        # Generate signature
        params['oauth_signature'] = self.generate_signature(
            'POST',
            f'{self.base_url}/oauth/access_token',
            params,
            self.request_token_secret
        )
        
        # Make request
        response = requests.post(
            f'{self.base_url}/oauth/access_token',
            data=params
        )
        
        if response.status_code == 200:
            data = response.json()
            self.access_token = data['oauth_token']
            self.access_token_secret = data['oauth_token_secret']
            return True
        return False

    def call_secure_endpoint(self):
        if not self.access_token:
            print("Access token not obtained")
            return

        params = {
            'oauth_consumer_key': self.consumer_key,
            'oauth_nonce': self.generate_nonce(),
            'oauth_signature_method': 'HMAC-SHA1',
            'oauth_timestamp': str(int(time.time())),
            'oauth_token': self.access_token,
            'oauth_version': '1.0'
        }
        
        # Generate signature
        params['oauth_signature'] = self.generate_signature(
            'GET',
            f'{self.base_url}/api/secure',
            params,
            self.access_token_secret
        )
        
        # Create Authorization header
        auth_header = 'OAuth ' + ', '.join(f'{k}="{urllib.parse.quote(str(v), safe="")}"' for k, v in params.items())
        
        # Make request
        response = requests.get(
            f'{self.base_url}/api/secure',
            headers={'Authorization': auth_header}
        )
        
        print(f'Status Code: {response.status_code}')
        print(f'Response: {response.json()}')

if __name__ == '__main__':
    client = OAuth1Client()
    
    # Get request token
    print("Getting request token...")
    if client.get_request_token():
        print("Request token obtained successfully")
        
        # Get access token
        print("\nGetting access token...")
        if client.get_access_token():
            print("Access token obtained successfully")
            
            # Call secure endpoint
            print("\nCalling secure endpoint...")
            client.call_secure_endpoint()
        else:
            print("Failed to get access token")
    else:
        print("Failed to get request token") 