from flask import Flask, jsonify, request, session
from functools import wraps
import oauthlib.oauth1
import time
import secrets
import json

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# In-memory storage for OAuth 1.0 data (for demonstration)
CONSUMERS = {
    'consumer_key_1': {
        'consumer_secret': 'consumer_secret_1',
        'name': 'Test App'
    }
}

REQUEST_TOKENS = {}
ACCESS_TOKENS = {}

def generate_token():
    return secrets.token_urlsafe(32)

def requires_oauth1(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('OAuth '):
            return jsonify({'message': 'OAuth 1.0 authentication required'}), 401

        try:
            # Parse OAuth parameters
            oauth_params = dict(param.split('=', 1) for param in auth_header[6:].split(', '))
            oauth_params = {k: v.strip('"') for k, v in oauth_params.items()}

            # Verify required parameters
            required_params = ['oauth_consumer_key', 'oauth_token', 'oauth_signature_method',
                             'oauth_timestamp', 'oauth_nonce', 'oauth_signature']
            if not all(param in oauth_params for param in required_params):
                return jsonify({'message': 'Missing required OAuth parameters'}), 400

            # Verify consumer
            consumer_key = oauth_params['oauth_consumer_key']
            if consumer_key not in CONSUMERS:
                return jsonify({'message': 'Invalid consumer key'}), 401

            # Verify access token
            access_token = oauth_params['oauth_token']
            if access_token not in ACCESS_TOKENS:
                return jsonify({'message': 'Invalid access token'}), 401

            # Verify timestamp (within 5 minutes)
            timestamp = int(oauth_params['oauth_timestamp'])
            if abs(time.time() - timestamp) > 300:
                return jsonify({'message': 'Request expired'}), 401

            # In a real implementation, you would verify the signature here
            # This is a simplified version for demonstration

            return f(*args, **kwargs)
        except Exception as e:
            return jsonify({'message': f'Authentication failed: {str(e)}'}), 401

    return decorated

@app.route('/oauth/request_token', methods=['POST'])
def request_token():
    # Verify consumer key
    consumer_key = request.form.get('oauth_consumer_key')
    if consumer_key not in CONSUMERS:
        return jsonify({'message': 'Invalid consumer key'}), 401

    # Generate request token
    request_token = generate_token()
    REQUEST_TOKENS[request_token] = {
        'consumer_key': consumer_key,
        'created_at': time.time()
    }

    return jsonify({
        'oauth_token': request_token,
        'oauth_token_secret': 'request_token_secret',
        'oauth_callback_confirmed': 'true'
    })

@app.route('/oauth/access_token', methods=['POST'])
def access_token():
    # Verify request token
    request_token = request.form.get('oauth_token')
    if request_token not in REQUEST_TOKENS:
        return jsonify({'message': 'Invalid request token'}), 401

    # Generate access token
    access_token = generate_token()
    ACCESS_TOKENS[access_token] = {
        'consumer_key': REQUEST_TOKENS[request_token]['consumer_key'],
        'created_at': time.time()
    }

    # Remove used request token
    del REQUEST_TOKENS[request_token]

    return jsonify({
        'oauth_token': access_token,
        'oauth_token_secret': 'access_token_secret'
    })

@app.route('/api/secure', methods=['GET'])
@requires_oauth1
def secure_endpoint():
    return jsonify({
        'message': 'This is a secure endpoint that requires OAuth 1.0 authentication',
        'status': 'success'
    })

if __name__ == '__main__':
    app.run(debug=True, port=5005) 