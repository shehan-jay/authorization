from flask import Flask, jsonify, request
from base_auth import BaseAuth
import secrets
import time

class BearerAuth(BaseAuth):
    def __init__(self):
        super().__init__()
        self.port = 5002
        # In-memory storage for tokens (for demonstration)
        self.tokens = {
            'admin': {
                'token': self.generate_token(),
                'expires_at': time.time() + 3600  # 1 hour expiration
            }
        }

    def generate_token(self):
        """Generate a random token."""
        return secrets.token_urlsafe(32)

    def authenticate(self, request):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return False

        try:
            # Extract token from header
            token = auth_header.split(' ')[1]

            # Check if token is valid
            for user_data in self.tokens.values():
                if (user_data['token'] == token and 
                    user_data['expires_at'] > time.time()):
                    return True
            return False
        except Exception:
            return False

    def get_token(self, username):
        """Get a token for a user."""
        if username in self.tokens:
            # Check if token is expired
            if self.tokens[username]['expires_at'] <= time.time():
                # Generate new token
                self.tokens[username] = {
                    'token': self.generate_token(),
                    'expires_at': time.time() + 3600
                }
            return self.tokens[username]['token']
        return None

app = Flask(__name__)
auth = BearerAuth()

@app.route('/api/token', methods=['POST'])
def get_token():
    username = request.json.get('username')
    if not username:
        return jsonify({
            'message': 'Username is required',
            'status': 'error'
        }), 400

    token = auth.get_token(username)
    if not token:
        return jsonify({
            'message': 'Invalid username',
            'status': 'error'
        }), 401

    return jsonify({
        'token': token,
        'expires_in': 3600,
        'status': 'success'
    })

@app.route('/api/secure', methods=['GET'])
@auth.requires_auth
def secure_endpoint():
    return jsonify({
        'message': 'This is a secure endpoint that requires Bearer Token authentication',
        'status': 'success'
    })

if __name__ == '__main__':
    app.run(debug=True, port=auth.get_port()) 