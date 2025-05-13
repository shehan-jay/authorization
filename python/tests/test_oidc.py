import unittest
import time
import jwt
from src.oidc.oidc import OIDC
from tests.test_utils import TestCase, run_auth_test

class TestOIDC(unittest.TestCase):
    def setUp(self):
        self.issuer = 'https://test-issuer.com'
        self.client_id = 'test_client_id'
        self.client_secret = 'test_client_secret'
        self.redirect_uri = 'https://test-client.com/callback'
        self.auth = OIDC(
            issuer=self.issuer,
            client_id=self.client_id,
            client_secret=self.client_secret,
            redirect_uri=self.redirect_uri
        )

    def create_id_token(self, expiration_time, nonce=None):
        """Create an ID token."""
        payload = {
            'iss': self.issuer,
            'sub': 'test_user',
            'aud': self.client_id,
            'exp': expiration_time,
            'iat': int(time.time()),
            'nonce': nonce or 'test_nonce'
        }
        return jwt.encode(payload, self.client_secret, algorithm='HS256')

    def test_valid_id_token(self):
        # Create a valid ID token
        valid_token = self.create_id_token(int(time.time()) + 3600)  # 1 hour from now
        test_case = TestCase(
            name='Valid ID token',
            auth_header=f'Bearer {valid_token}',
            expected_status=200,
            expected_error=False
        )
        run_auth_test(test_case, self.auth, self)

    def test_expired_id_token(self):
        # Create an expired ID token
        expired_token = self.create_id_token(int(time.time()) - 3600)  # 1 hour ago
        test_case = TestCase(
            name='Expired ID token',
            auth_header=f'Bearer {expired_token}',
            expected_status=401,
            expected_error=True
        )
        run_auth_test(test_case, self.auth, self)

    def test_invalid_issuer(self):
        # Create a token with invalid issuer
        invalid_issuer_token = jwt.encode(
            {
                'iss': 'https://invalid-issuer.com',
                'sub': 'test_user',
                'aud': self.client_id,
                'exp': int(time.time()) + 3600,
                'iat': int(time.time())
            },
            self.client_secret,
            algorithm='HS256'
        )
        test_case = TestCase(
            name='Invalid issuer',
            auth_header=f'Bearer {invalid_issuer_token}',
            expected_status=401,
            expected_error=True
        )
        run_auth_test(test_case, self.auth, self)

    def test_invalid_audience(self):
        # Create a token with invalid audience
        invalid_audience_token = jwt.encode(
            {
                'iss': self.issuer,
                'sub': 'test_user',
                'aud': 'invalid_client_id',
                'exp': int(time.time()) + 3600,
                'iat': int(time.time())
            },
            self.client_secret,
            algorithm='HS256'
        )
        test_case = TestCase(
            name='Invalid audience',
            auth_header=f'Bearer {invalid_audience_token}',
            expected_status=401,
            expected_error=True
        )
        run_auth_test(test_case, self.auth, self)

    def test_missing_id_token(self):
        test_case = TestCase(
            name='Missing ID token',
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

    def test_invalid_scheme(self):
        test_case = TestCase(
            name='Invalid scheme',
            auth_header='Basic token',
            expected_status=401,
            expected_error=True
        )
        run_auth_test(test_case, self.auth, self)

    def test_get_type(self):
        self.assertEqual(self.auth.get_type(), 'oidc')

if __name__ == '__main__':
    unittest.main() 