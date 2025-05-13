import unittest
import time
import jwt
from src.asap.asap import ASAP
from tests.test_utils import TestCase, run_auth_test

class TestASAP(unittest.TestCase):
    def setUp(self):
        self.issuer = 'test_issuer'
        self.audience = 'test_audience'
        self.private_key = 'test_private_key'
        self.auth = ASAP(
            issuer=self.issuer,
            audience=self.audience,
            private_key=self.private_key
        )

    def create_asap_token(self, expiration_time):
        """Create an ASAP token."""
        payload = {
            'iss': self.issuer,
            'aud': self.audience,
            'exp': expiration_time,
            'iat': int(time.time())
        }
        return jwt.encode(payload, self.private_key, algorithm='RS256')

    def test_valid_asap_auth(self):
        # Create a valid ASAP token
        valid_token = self.create_asap_token(int(time.time()) + 3600)  # 1 hour from now
        test_case = TestCase(
            name='Valid ASAP authentication',
            auth_header=f'Bearer {valid_token}',
            expected_status=200,
            expected_error=False
        )
        run_auth_test(test_case, self.auth, self)

    def test_expired_asap_token(self):
        # Create an expired ASAP token
        expired_token = self.create_asap_token(int(time.time()) - 3600)  # 1 hour ago
        test_case = TestCase(
            name='Expired ASAP token',
            auth_header=f'Bearer {expired_token}',
            expected_status=401,
            expected_error=True
        )
        run_auth_test(test_case, self.auth, self)

    def test_invalid_asap_token(self):
        # Create an invalid ASAP token
        invalid_token = 'invalid_token'
        test_case = TestCase(
            name='Invalid ASAP token',
            auth_header=f'Bearer {invalid_token}',
            expected_status=401,
            expected_error=True
        )
        run_auth_test(test_case, self.auth, self)

    def test_missing_asap_token(self):
        test_case = TestCase(
            name='Missing ASAP token',
            auth_header=None,
            expected_status=401,
            expected_error=True
        )
        run_auth_test(test_case, self.auth, self)

    def test_malformed_asap_header(self):
        test_case = TestCase(
            name='Malformed ASAP header',
            auth_header='Bearer',
            expected_status=401,
            expected_error=True
        )
        run_auth_test(test_case, self.auth, self)

    def test_invalid_scheme(self):
        test_case = TestCase(
            name='Invalid scheme',
            auth_header='Basic token',
            expected_status=401,
            expected_error=True
        )
        run_auth_test(test_case, self.auth, self)

    def test_get_type(self):
        self.assertEqual(self.auth.get_type(), 'asap')

if __name__ == '__main__':
    unittest.main() 