import unittest
import time
import hmac
import hashlib
import base64
from src.hawk_auth.hawk_auth import HawkAuth
from tests.test_utils import TestCase, run_auth_test

class TestHawkAuth(unittest.TestCase):
    def setUp(self):
        self.id = 'test_hawk_id'
        self.key = 'test_hawk_key'
        self.algorithm = 'sha256'
        self.auth = HawkAuth(
            id=self.id,
            key=self.key,
            algorithm=self.algorithm
        )

    def create_hawk_header(self, timestamp, nonce, ext=''):
        """Create a Hawk authentication header."""
        mac = hmac.new(
            self.key.encode(),
            f'hawk.1.header\n{timestamp}\n{nonce}\nGET\n/\n\n{ext}\n'.encode(),
            hashlib.sha256
        ).digest()
        mac_b64 = base64.b64encode(mac).decode()
        
        return f'Hawk id="{self.id}", ts="{timestamp}", nonce="{nonce}", mac="{mac_b64}", ext="{ext}"'

    def test_valid_hawk_auth(self):
        timestamp = str(int(time.time()))
        nonce = 'test_nonce'
        auth_header = self.create_hawk_header(timestamp, nonce)
        
        test_case = TestCase(
            name='Valid Hawk authentication',
            auth_header=auth_header,
            expected_status=200,
            expected_error=False
        )
        run_auth_test(test_case, self.auth, self)

    def test_invalid_hawk_auth(self):
        # Create an invalid Hawk authentication header
        invalid_header = f'Hawk id="{self.id}", ts="1234567890", nonce="test_nonce", mac="invalid_mac", ext=""'
        test_case = TestCase(
            name='Invalid Hawk authentication',
            auth_header=invalid_header,
            expected_status=401,
            expected_error=True
        )
        run_auth_test(test_case, self.auth, self)

    def test_missing_hawk_header(self):
        test_case = TestCase(
            name='Missing Hawk header',
            auth_header=None,
            expected_status=401,
            expected_error=True
        )
        run_auth_test(test_case, self.auth, self)

    def test_malformed_hawk_header(self):
        test_case = TestCase(
            name='Malformed Hawk header',
            auth_header='Hawk',
            expected_status=401,
            expected_error=True
        )
        run_auth_test(test_case, self.auth, self)

    def test_expired_timestamp(self):
        # Create a Hawk header with expired timestamp
        expired_timestamp = str(int(time.time()) - 3600)  # 1 hour ago
        expired_header = self.create_hawk_header(expired_timestamp, 'test_nonce')
        test_case = TestCase(
            name='Expired timestamp',
            auth_header=expired_header,
            expected_status=401,
            expected_error=True
        )
        run_auth_test(test_case, self.auth, self)

    def test_get_type(self):
        self.assertEqual(self.auth.get_type(), 'hawk')

if __name__ == '__main__':
    unittest.main() 