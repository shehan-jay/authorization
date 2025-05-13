import unittest
import requests
from src.basic_auth.server import BasicAuth, app
from src.basic_auth.client import BasicAuthClient
import base64
from src.basic_auth.basic_auth import BasicAuth
from tests.test_utils import TestCase, run_auth_test


class TestBasicAuth(unittest.TestCase):
    """Test cases for Basic Authentication implementation."""

    def setUp(self):
        """Set up test environment."""
        self.auth = BasicAuth({
            'test-user': 'test-password'
        })
        self.client = BasicAuthClient()
        self.app = app.test_client()

    def test_valid_credentials(self):
        credentials = base64.b64encode(b'test-user:test-password').decode('utf-8')
        test_case = TestCase(
            name='Valid credentials',
            auth_header=f'Basic {credentials}',
            expected_status=200,
            expected_error=False
        )
        run_auth_test(test_case, self.auth, self)

    def test_invalid_credentials(self):
        credentials = base64.b64encode(b'wrong-user:wrong-password').decode('utf-8')
        test_case = TestCase(
            name='Invalid credentials',
            auth_header=f'Basic {credentials}',
            expected_status=401,
            expected_error=True
        )
        run_auth_test(test_case, self.auth, self)

    def test_missing_credentials(self):
        test_case = TestCase(
            name='Missing credentials',
            auth_header=None,
            expected_status=401,
            expected_error=True
        )
        run_auth_test(test_case, self.auth, self)

    def test_malformed_header(self):
        test_case = TestCase(
            name='Malformed header',
            auth_header='Basic',
            expected_status=401,
            expected_error=True
        )
        run_auth_test(test_case, self.auth, self)

    def test_invalid_scheme(self):
        test_case = TestCase(
            name='Invalid scheme',
            auth_header='Bearer token',
            expected_status=401,
            expected_error=True
        )
        run_auth_test(test_case, self.auth, self)

    def test_get_type(self):
        self.assertEqual(self.auth.get_type(), 'basic')

    def test_authenticate_valid_credentials(self):
        """Test authentication with valid credentials."""
        credentials = f"admin:password123"
        encoded = base64.b64encode(credentials.encode("utf-8")).decode("utf-8")
        headers = {"Authorization": f"Basic {encoded}"}
        
        response = self.app.get("/api/secure", headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["status"], "success")

    def test_authenticate_invalid_credentials(self):
        """Test authentication with invalid credentials."""
        credentials = f"admin:wrongpassword"
        encoded = base64.b64encode(credentials.encode("utf-8")).decode("utf-8")
        headers = {"Authorization": f"Basic {encoded}"}
        
        response = self.app.get("/api/secure", headers=headers)
        self.assertEqual(response.status_code, 401)

    def test_authenticate_missing_header(self):
        """Test authentication with missing Authorization header."""
        response = self.app.get("/api/secure")
        self.assertEqual(response.status_code, 401)

    def test_authenticate_malformed_header(self):
        """Test authentication with malformed Authorization header."""
        headers = {"Authorization": "Basic invalid_base64"}
        response = self.app.get("/api/secure", headers=headers)
        self.assertEqual(response.status_code, 401)

    def test_client_auth_header(self):
        """Test client's auth header generation."""
        header = self.client.get_auth_header()
        self.assertTrue(header.startswith("Basic "))
        self.assertTrue(len(header) > 6)  # Basic + space + encoded credentials

    def test_port_setting(self):
        """Test port setting functionality."""
        test_port = 5002
        self.auth.set_port(test_port)
        self.assertEqual(self.auth.get_port(), test_port)


if __name__ == "__main__":
    unittest.main() 