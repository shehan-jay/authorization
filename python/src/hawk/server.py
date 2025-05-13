from flask import Flask, jsonify, request
from functools import wraps
import hmac
import hashlib
import time
import base64
import json

app = Flask(__name__)

# In-memory storage for Hawk credentials (for demonstration)
CREDENTIALS = {
    'hawk_id_1': {
        'key': 'hawk_key_1',
        'algorithm': 'sha256'
    }
}

def generate_mac(credentials, timestamp, nonce, method, uri, host, port, payload_hash=None):
    # Create normalized string
    normalized = f"hawk.1.header\n{timestamp}\n{nonce}\n{method}\n{uri}\n{host}\n{port}\n{payload_hash or ''}\n\n"
    
    # Calculate MAC
    mac = hmac.new(
        credentials['key'].encode('utf-8'),
        normalized.encode('utf-8'),
        getattr(hashlib, credentials['algorithm'])
    ).digest()
    
    return base64.b64encode(mac).decode('utf-8')

def requires_hawk_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Hawk '):
            return jsonify({'message': 'Hawk authentication required'}), 401

        try:
            # Parse Hawk parameters
            hawk_params = dict(param.split('=', 1) for param in auth_header[5:].split(', '))
            hawk_params = {k: v.strip('"') for k, v in hawk_params.items()}

            # Verify required parameters
            required_params = ['id', 'ts', 'nonce', 'mac']
            if not all(param in hawk_params for param in required_params):
                return jsonify({'message': 'Missing required Hawk parameters'}), 400

            # Verify credentials
            hawk_id = hawk_params['id']
            if hawk_id not in CREDENTIALS:
                return jsonify({'message': 'Invalid Hawk ID'}), 401

            credentials = CREDENTIALS[hawk_id]

            # Verify timestamp (within 60 seconds)
            timestamp = int(hawk_params['ts'])
            if abs(time.time() - timestamp) > 60:
                return jsonify({'message': 'Request expired'}), 401

            # Calculate payload hash if present
            payload_hash = None
            if request.data:
                payload_hash = base64.b64encode(
                    hashlib.sha256(request.data).digest()
                ).decode('utf-8')

            # Calculate expected MAC
            expected_mac = generate_mac(
                credentials,
                hawk_params['ts'],
                hawk_params['nonce'],
                request.method,
                request.path,
                request.host,
                request.environ.get('SERVER_PORT', '80'),
                payload_hash
            )

            # Verify MAC
            if hawk_params['mac'] != expected_mac:
                return jsonify({'message': 'Invalid MAC'}), 401

            return f(*args, **kwargs)
        except Exception as e:
            return jsonify({'message': f'Authentication failed: {str(e)}'}), 401

    return decorated

@app.route('/api/secure', methods=['GET', 'POST'])
@requires_hawk_auth
def secure_endpoint():
    return jsonify({
        'message': 'This is a secure endpoint that requires Hawk authentication',
        'status': 'success'
    })

if __name__ == '__main__':
    app.run(debug=True, port=5007) 