from flask import Flask, jsonify, request
from functools import wraps
import jwt
import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # In production, use a secure secret key

def generate_token(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24),
        'iat': datetime.datetime.utcnow()
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def requires_jwt(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return {'message': 'JWT token required'}, 401
        
        token = auth_header.split(' ')[1]
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            request.user_id = payload['user_id']
        except jwt.ExpiredSignatureError:
            return {'message': 'Token has expired'}, 401
        except jwt.InvalidTokenError:
            return {'message': 'Invalid token'}, 401
        
        return f(*args, **kwargs)
    return decorated

@app.route('/api/token', methods=['POST'])
def get_token():
    # In a real application, you would validate credentials here
    user_id = 'user123'  # In real app, this would be the authenticated user's ID
    token = generate_token(user_id)
    return jsonify({
        'access_token': token,
        'token_type': 'Bearer',
        'expires_in': 86400
    })

@app.route('/api/secure', methods=['GET'])
@requires_jwt
def secure_endpoint():
    return jsonify({
        'message': 'This is a secure endpoint that requires JWT bearer authentication',
        'status': 'success',
        'user_id': request.user_id
    })

if __name__ == '__main__':
    app.run(debug=True, port=5003) 