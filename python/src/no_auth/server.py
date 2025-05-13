from flask import Flask, jsonify
from base_auth import BaseAuth

class NoAuth(BaseAuth):
    def __init__(self):
        super().__init__()
        self.port = 5000

    def authenticate(self, request):
        # No authentication required
        return True

app = Flask(__name__)
auth = NoAuth()

@app.route('/api/public', methods=['GET'])
@auth.requires_auth
def public_endpoint():
    return jsonify({
        'message': 'This is a public endpoint that requires no authentication',
        'status': 'success'
    })

if __name__ == '__main__':
    app.run(debug=True, port=auth.get_port()) 