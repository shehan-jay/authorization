import requests
import jwt
import time

class JWTokenClient:
    def __init__(self, base_url='http://localhost:5003'):
        self.base_url = base_url
        self.token = None

    def get_token(self):
        response = requests.post(f'{self.base_url}/api/token')
        if response.status_code == 200:
            self.token = response.json()['access_token']
            return self.token
        return None

    def decode_token(self):
        if not self.token:
            return None
        try:
            # Note: In a real application, you would need the secret key to decode
            # This is just for demonstration
            return jwt.decode(self.token, options={"verify_signature": False})
        except jwt.InvalidTokenError:
            return None

    def call_secure_endpoint(self):
        if not self.token:
            print("No token available. Getting new token...")
            self.get_token()

        headers = {'Authorization': f'Bearer {self.token}'}
        try:
            response = requests.get(f'{self.base_url}/api/secure', headers=headers)
            print(f'Status Code: {response.status_code}')
            print(f'Response: {response.json()}')
            
            # Show token information
            token_data = self.decode_token()
            if token_data:
                print("\nToken Information:")
                print(f"User ID: {token_data.get('user_id')}")
                print(f"Expires at: {time.ctime(token_data.get('exp'))}")
        except requests.exceptions.RequestException as e:
            print(f'Error: {e}')

if __name__ == '__main__':
    client = JWTokenClient()
    
    # Test with valid token
    print("Testing with valid token:")
    client.call_secure_endpoint()
    
    # Test with invalid token
    print("\nTesting with invalid token:")
    client.token = "invalid_token"
    client.call_secure_endpoint() 