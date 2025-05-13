import unittest
import time
from src.oauth1.oauth1 import OAuth1
from tests.test_utils import TestCase, run_auth_test

class TestOAuth1(unittest.TestCase):
    def setUp(self):
        self.consumer_key = 'test_consumer_key'
        self.consumer_secret = 'test_consumer_secret'
        self.token = 'test_token'
        self.token_secret = 'test_token_secret'
        self.auth = OAuth1(
            consumer_key=self.consumer_key,
            consumer_secret=self.consumer_secret,
            token=self.token,
            token_secret=self.token_secret
        )

    def test_valid_oauth1_request(self):
        test_case = TestCase(
            name='Valid OAuth 1.0 request',
            auth_header=self.auth.get_auth_header('GET', 'http://localhost:8000'),
            expected_status=200,
            expected_error=False
        )
        run_auth_test(test_case, self.auth, self)

    def test_invalid_signature(self):
        # Create a header with invalid signature
        invalid_header = 'OAuth oauth_consumer_key="test_consumer_key",oauth_signature="invalid",oauth_signature_method="HMAC-SHA1",oauth_timestamp="1234567890",oauth_nonce="test_nonce",oauth_version="1.0"'
        test_case = TestCase(
            name='Invalid signature',
            auth_header=invalid_header,
            expected_status=401,
            expected_error=True
        )
        run_auth_test(test_case, self.auth, self)

    def test_missing_oauth_header(self):
        test_case = TestCase(
            name='Missing OAuth header',
            auth_header=None,
            expected_status=401,
            expected_error=True
        )
        run_auth_test(test_case, self.auth, self)

    def test_malformed_oauth_header(self):
        test_case = TestCase(
            name='Malformed OAuth header',
            auth_header='OAuth',
            expected_status=401,
            expected_error=True
        )
        run_auth_test(test_case, self.auth, self)

    def test_expired_timestamp(self):
        # Create a header with expired timestamp
        expired_timestamp = str(int(time.time()) - 3600)  # 1 hour ago
        expired_header = f'OAuth oauth_consumer_key="{self.consumer_key}",oauth_signature="test",oauth_signature_method="HMAC-SHA1",oauth_timestamp="{expired_timestamp}",oauth_nonce="test_nonce",oauth_version="1.0"'
        test_case = TestCase(
            name='Expired timestamp',
            auth_header=expired_header,
            expected_status=401,
            expected_error=True
        )
        run_auth_test(test_case, self.auth, self)

    def test_get_type(self):
        self.assertEqual(self.auth.get_type(), 'oauth1')

if __name__ == '__main__':
    unittest.main() 