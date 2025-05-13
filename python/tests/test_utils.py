import unittest
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import requests
from urllib.parse import urlparse, urlencode

class TestServer(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'Success')

    def do_POST(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'Success')

class TestCase:
    def __init__(self, name, auth_header=None, query_params=None, expected_status=200, expected_error=False):
        self.name = name
        self.auth_header = auth_header
        self.query_params = query_params
        self.expected_status = expected_status
        self.expected_error = expected_error

def run_auth_test(test_case, auth_handler, test_instance):
    """Run a test case for an authentication method."""
    # Start test server
    server = HTTPServer(('localhost', 0), TestServer)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()

    try:
        # Get server port
        port = server.server_port

        # Make request
        headers = {}
        if test_case.auth_header:
            headers['Authorization'] = test_case.auth_header

        # Build URL with query parameters
        url = f'http://localhost:{port}'
        if test_case.query_params:
            url += '?' + urlencode(test_case.query_params)

        response = requests.get(url, headers=headers)

        # Check status code
        test_instance.assertEqual(response.status_code, test_case.expected_status)

        # Check if authentication error occurred
        if test_case.expected_error:
            test_instance.assertEqual(response.status_code, 401)
    finally:
        # Clean up
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=1) 