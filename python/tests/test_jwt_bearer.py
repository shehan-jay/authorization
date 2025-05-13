import unittest
import jwt
import time
from src.jwt_bearer.jwt_bearer import JWTBearer
from tests.test_utils import TestCase, run_auth_test

class TestJWTBearer(unittest.TestCase):
    def setUp(self):
        self.secret_key = 'your-secret-key'
        self.auth = JWTBearer(self.secret_key)

    def create_test_jwt(self, secret_key, expiration_time):
        """Create a test JWT token."""
        payload = {
            'sub': 'test-user',
            'exp': expiration_time,
            'iat': int(time.time())
        }
        return jwt.encode(payload, secret_key, algorithm='HS256')

    def test_valid_jwt_token(self):
        # Create a valid token
        valid_token = self.create_test_jwt(
            self.secret_key,
            int(time.time()) + 3600  # 1 hour from now
        )
        test_case = TestCase(
            name='Valid JWT token',
            auth_header=f'Bearer {valid_token}',
            expected_status=200,
            expected_error=False
        )
        run_auth_test(test_case, self.auth, self)

    def test_expired_jwt_token(self):
        # Create an expired token
        expired_token = self.create_test_jwt(
            self.secret_key,
            int(time.time()) - 3600  # 1 hour ago
        )
        test_case = TestCase(
            name='Expired JWT token',
            auth_header=f'Bearer {expired_token}',
            expected_status=401,
            expected_error=True
        )
        run_auth_test(test_case, self.auth, self)

    def test_invalid_signature(self):
        # Create a token with invalid signature
        invalid_token = self.create_test_jwt(
            'wrong-secret-key',
            int(time.time()) + 3600
        )
        test_case = TestCase(
            name='Invalid signature',
            auth_header=f'Bearer {invalid_token}',
            expected_status=401,
            expected_error=True
        )
        run_auth_test(test_case, self.auth, self)

    def test_missing_token(self):
        test_case = TestCase(
            name='Missing token',
            auth_header=None,
            expected_status=401,
            expected_error=True
        )
        run_auth_test(test_case, self.auth, self)

    def test_malformed_header(self):
        test_case = TestCase(
            name='Malformed header',
            auth_header='Bearer',
            expected_status=401,
            expected_error=True
        )
        run_auth_test(test_case, self.auth, self)

    def test_get_type(self):
        self.assertEqual(self.auth.get_type(), 'jwt')

if __name__ == '__main__':
    unittest.main() 