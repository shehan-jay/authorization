import requests
import json

class APIKeyClient:
    def __init__(self, base_url, api_key):
        self.base_url = base_url
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            'X-API-Key': api_key,
            'Content-Type': 'application/json'
        })

    def create_api_key(self, user_id, permissions=None, expires_in_days=30):
        """Create a new API key"""
        response = self.session.post(
            f'{self.base_url}/api/keys',
            json={
                'user_id': user_id,
                'permissions': permissions,
                'expires_in_days': expires_in_days
            }
        )
        return response.json()

    def call_secure_endpoint(self, method='GET', data=None):
        """Call the secure endpoint with API key authentication"""
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
    client = APIKeyClient(
        'http://localhost:5010',
        'sk_test_51H7qXKJw3Jw3Jw3Jw3Jw3Jw3'
    )

    # Test GET request
    get_response = client.call_secure_endpoint('GET')
    print('GET Response:', json.dumps(get_response, indent=2))

    # Test POST request
    post_data = {'message': 'Hello from API Key client!'}
    post_response = client.call_secure_endpoint('POST', post_data)
    print('POST Response:', json.dumps(post_response, indent=2))

if __name__ == '__main__':
    main() 