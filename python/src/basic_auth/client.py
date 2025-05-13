import requests
import base64
from typing import Dict, Any


class BasicAuthClient:
    """Client for making authenticated requests using Basic Authentication."""

    def __init__(self, base_url: str = "http://localhost:5001") -> None:
        """Initialize the Basic Authentication client.
        
        Args:
            base_url: The base URL of the server.
        """
        self.base_url = base_url
        self.username = "admin"
        self.password = "password123"

    def get_auth_header(self) -> str:
        """Generate the Basic Authentication header.
        
        Returns:
            str: The Authorization header value.
        """
        credentials = f"{self.username}:{self.password}"
        encoded_credentials = base64.b64encode(credentials.encode("utf-8")).decode("utf-8")
        return f"Basic {encoded_credentials}"

    def call_secure_endpoint(self) -> None:
        """Make a request to the secure endpoint with Basic Authentication."""
        try:
            headers: Dict[str, str] = {"Authorization": self.get_auth_header()}
            response = requests.get(f"{self.base_url}/api/secure", headers=headers)
            print(f"Status Code: {response.status_code}")
            print(f"Response: {response.json()}")
        except Exception as e:
            print(f"Error: {str(e)}")


if __name__ == "__main__":
    client = BasicAuthClient()
    print("Testing Basic Authentication...")
    client.call_secure_endpoint() 