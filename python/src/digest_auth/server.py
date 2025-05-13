from flask import Flask, jsonify, request, make_response
from functools import wraps
import hashlib
import time
import random
import string

app = Flask(__name__)

# In-memory user database (for demonstration)
USERS = {
    'admin': 'password123',
    'user': 'userpass'
}

# In-memory nonce storage (for demonstration)
NONCES = {}

def generate_nonce():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=32))

def calculate_digest(username, realm, password, nonce, nc, cnonce, qop, method, uri):
    ha1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()
    ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
    
    if qop == 'auth':
        response = hashlib.md5(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}".encode()).hexdigest()
    else:
        response = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
    
    return response

def requires_digest_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        
        if not auth_header or not auth_header.startswith('Digest '):
            nonce = generate_nonce()
            NONCES[nonce] = time.time()
            
            response = make_response(jsonify({'message': 'Digest authentication required'}), 401)
            response.headers['WWW-Authenticate'] = (
                f'Digest realm="Secure Area", '
                f'nonce="{nonce}", '
                f'qop="auth"'
            )
            return response
        
        # Parse digest parameters
        auth_params = dict(param.split('=', 1) for param in auth_header[7:].split(', '))
        auth_params = {k: v.strip('"') for k, v in auth_params.items()}
        
        username = auth_params.get('username')
        nonce = auth_params.get('nonce')
        nc = auth_params.get('nc')
        cnonce = auth_params.get('cnonce')
        qop = auth_params.get('qop')
        uri = auth_params.get('uri')
        response = auth_params.get('response')
        
        if not all([username, nonce, nc, cnonce, qop, uri, response]):
            return jsonify({'message': 'Invalid digest parameters'}), 400
        
        if username not in USERS:
            return jsonify({'message': 'Invalid credentials'}), 401
        
        if nonce not in NONCES:
            return jsonify({'message': 'Invalid nonce'}), 401
        
        # Clean up old nonces
        current_time = time.time()
        NONCES = {n: t for n, t in NONCES.items() if current_time - t < 300}  # 5 minutes
        
        expected_response = calculate_digest(
            username, 'Secure Area', USERS[username],
            nonce, nc, cnonce, qop, request.method, uri
        )
        
        if response != expected_response:
            return jsonify({'message': 'Invalid credentials'}), 401
        
        return f(*args, **kwargs)
    return decorated

@app.route('/api/secure', methods=['GET'])
@requires_digest_auth
def secure_endpoint():
    return jsonify({
        'message': 'This is a secure endpoint that requires digest authentication',
        'status': 'success'
    })

if __name__ == '__main__':
    app.run(debug=True, port=5004) 