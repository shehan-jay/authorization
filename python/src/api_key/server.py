from flask import Flask, jsonify, request
from base_auth import BaseAuth
import secrets
import time

class APIKeyAuth(BaseAuth):
    def __init__(self):
        super().__init__()
        self.port = 5010
        # In-memory storage for API keys (for demonstration)
        self.api_keys = {
            'sk_test_51H7qXKJw3Jw3Jw3Jw3Jw3Jw3': {
                'user_id': 'user_123',
                'created_at': time.time(),
                'expires_at': time.time() + (30 * 24 * 60 * 60),  # 30 days
                'permissions': ['read', 'write']
            }
        }

    def generate_api_key(self, user_id, permissions=None, expires_in_days=30):
        """Generate a new API key for a user"""
        api_key = f'sk_test_{secrets.token_hex(16)}'
        self.api_keys[api_key] = {
            'user_id': user_id,
            'created_at': time.time(),
            'expires_at': time.time() + (expires_in_days * 24 * 60 * 60),
            'permissions': permissions or ['read']
        }
        return api_key

    def authenticate(self, request):
        """Authenticate the request using API key"""
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            return False

        # Check if API key exists and is valid
        if api_key not in self.api_keys:
            return False

        key_info = self.api_keys[api_key]
        
        # Check if API key has expired
        if time.time() > key_info['expires_at']:
            return False

        # Store user info in request context for later use
        request.user_id = key_info['user_id']
        request.permissions = key_info['permissions']
        
        return True

app = Flask(__name__)
auth = APIKeyAuth()

@app.route('/api/keys', methods=['POST'])
def create_api_key():
    """Endpoint to create a new API key"""
    data = request.get_json()
    user_id = data.get('user_id')
    permissions = data.get('permissions', ['read'])
    expires_in_days = data.get('expires_in_days', 30)

    if not user_id:
        return jsonify({'error': 'user_id is required'}), 400

    api_key = auth.generate_api_key(user_id, permissions, expires_in_days)
    return jsonify({
        'api_key': api_key,
        'user_id': user_id,
        'permissions': permissions,
        'expires_in_days': expires_in_days
    })

@app.route('/api/secure', methods=['GET', 'POST'])
@auth.requires_auth
def secure_endpoint():
    """Secure endpoint that requires API key authentication"""
    response = {
        'message': 'This is a secure endpoint that requires API Key authentication',
        'status': 'success',
        'user_id': request.user_id,
        'permissions': request.permissions
    }

    if request.method == 'POST':
        response['received_data'] = request.get_json()

    return jsonify(response)

if __name__ == '__main__':
    app.run(debug=True, port=auth.get_port()) 