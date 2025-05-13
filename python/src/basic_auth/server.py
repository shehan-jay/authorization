from flask import Flask, jsonify, request
from typing import Dict, Any
from ..base_auth import BaseAuth
import base64


class BasicAuth(BaseAuth):
    """Basic Authentication handler implementation."""

    def __init__(self) -> None:
        """Initialize Basic Authentication handler with default credentials."""
        super().__init__()
        self.port = 5001
        # In-memory storage for credentials (for demonstration)
        self.credentials: Dict[str, str] = {
            "admin": "password123"
        }

    def authenticate(self, request: Any) -> bool:
        """Authenticate the request using Basic Authentication.
        
        Args:
            request: The request object to authenticate.
            
        Returns:
            bool: True if authentication is successful, False otherwise.
        """
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Basic "):
            return False

        try:
            # Decode the base64 encoded credentials
            encoded_credentials = auth_header.split(" ")[1]
            decoded_credentials = base64.b64decode(encoded_credentials).decode("utf-8")
            username, password = decoded_credentials.split(":")

            # Check if credentials are valid
            return username in self.credentials and self.credentials[username] == password
        except Exception:
            return False


app = Flask(__name__)
auth = BasicAuth()


@app.route("/api/secure", methods=["GET"])
@auth.requires_auth
def secure_endpoint() -> tuple[Dict[str, str], int]:
    """Secure endpoint that requires Basic Authentication.
    
    Returns:
        tuple[Dict[str, str], int]: JSON response and status code.
    """
    return jsonify({
        "message": "This is a secure endpoint that requires Basic Authentication",
        "status": "success"
    }), 200


if __name__ == "__main__":
    app.run(debug=True, port=auth.get_port()) 