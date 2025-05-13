from flask import Flask, jsonify, request
from base_auth import BaseAuth
import base64

class BasicAuth(BaseAuth):
    def __init__(self):
        super().__init__()
        self.port = 5001
        # In-memory storage for credentials (for demonstration)
        self.credentials = {
            'admin': 'password123'
        }

    def authenticate(self, request):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Basic '):
            return False

        try:
            # Decode the base64 encoded credentials
            encoded_credentials = auth_header.split(' ')[1]
            decoded_credentials = base64.b64decode(encoded_credentials).decode('utf-8')
            username, password = decoded_credentials.split(':')

            # Check if credentials are valid
            return username in self.credentials and self.credentials[username] == password
        except Exception:
            return False

app = Flask(__name__)
auth = BasicAuth()

@app.route('/api/secure', methods=['GET'])
@auth.requires_auth
def secure_endpoint():
    return jsonify({
        'message': 'This is a secure endpoint that requires Basic Authentication',
        'status': 'success'
    })

if __name__ == '__main__':
    app.run(debug=True, port=auth.get_port()) 