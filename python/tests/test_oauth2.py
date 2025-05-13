import unittest
import time
from src.oauth2.oauth2 import OAuth2
from tests.test_utils import TestCase, run_auth_test

class TestOAuth2(unittest.TestCase):
    def setUp(self):
        self.client_id = 'test_client_id'
        self.client_secret = 'test_client_secret'
        self.token_url = 'http://localhost:8000/oauth/token'
        self.auth = OAuth2(
            client_id=self.client_id,
            client_secret=self.client_secret,
            token_url=self.token_url
        )

    def test_valid_access_token(self):
        # Create a valid access token
        valid_token = 'valid_access_token'
        test_case = TestCase(
            name='Valid access token',
            auth_header=f'Bearer {valid_token}',
            expected_status=200,
            expected_error=False
        )
        run_auth_test(test_case, self.auth, self)

    def test_expired_access_token(self):
        # Create an expired access token
        expired_token = 'expired_access_token'
        test_case = TestCase(
            name='Expired access token',
            auth_header=f'Bearer {expired_token}',
            expected_status=401,
            expected_error=True
        )
        run_auth_test(test_case, self.auth, self)

    def test_invalid_access_token(self):
        test_case = TestCase(
            name='Invalid access token',
            auth_header='Bearer invalid_token',
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

    def test_invalid_scheme(self):
        test_case = TestCase(
            name='Invalid scheme',
            auth_header='Basic token',
            expected_status=401,
            expected_error=True
        )
        run_auth_test(test_case, self.auth, self)

    def test_get_type(self):
        self.assertEqual(self.auth.get_type(), 'oauth2')

if __name__ == '__main__':
    unittest.main() 