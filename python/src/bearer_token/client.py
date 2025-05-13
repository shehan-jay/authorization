import requests
import json

class BearerAuthClient:
    def __init__(self, base_url='http://localhost:5002'):
        self.base_url = base_url
        self.token = None

    def get_token(self):
        """Get a bearer token from the server."""
        try:
            response = requests.post(
                f"{self.base_url}/api/token",
                json={'username': 'admin'}
            )
            if response.status_code == 200:
                self.token = response.json()['token']
                print(f"Token obtained successfully: {self.token}")
            else:
                print(f"Failed to get token: {response.json()}")
        except Exception as e:
            print(f"Error getting token: {str(e)}")

    def call_secure_endpoint(self):
        """Call the secure endpoint using the bearer token."""
        if not self.token:
            print("No token available. Please get a token first.")
            return

        try:
            headers = {'Authorization': f'Bearer {self.token}'}
            response = requests.get(f"{self.base_url}/api/secure", headers=headers)
            print(f'Status Code: {response.status_code}')
            print(f'Response: {response.json()}')
        except Exception as e:
            print(f"Error: {str(e)}")

if __name__ == '__main__':
    client = BearerAuthClient()
    print("Testing Bearer Token Authentication...")
    
    # First, get a token
    print("\nGetting token...")
    client.get_token()
    
    # Then, call the secure endpoint
    print("\nCalling secure endpoint...")
    client.call_secure_endpoint() 