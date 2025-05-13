import unittest
import time
import hmac
import hashlib
import base64
from src.edgegrid.edgegrid import EdgeGrid
from tests.test_utils import TestCase, run_auth_test

class TestEdgeGrid(unittest.TestCase):
    def setUp(self):
        self.client_token = 'test_client_token'
        self.client_secret = 'test_client_secret'
        self.access_token = 'test_access_token'
        self.auth = EdgeGrid(
            client_token=self.client_token,
            client_secret=self.client_secret,
            access_token=self.access_token
        )

    def create_edgegrid_header(self, timestamp, nonce):
        """Create an EdgeGrid authentication header."""
        data = f'{timestamp}\t{nonce}\tGET\t/\t\n'
        signature = hmac.new(
            self.client_secret.encode(),
            data.encode(),
            hashlib.sha256
        ).digest()
        signature_b64 = base64.b64encode(signature).decode()
        
        return f'EG1-HMAC-SHA256 client_token={self.client_token};access_token={self.access_token};timestamp={timestamp};nonce={nonce};signature={signature_b64}'

    def test_valid_edgegrid_auth(self):
        timestamp = time.strftime('%Y%m%dT%H:%M:%S+0000', time.gmtime())
        nonce = 'test_nonce'
        auth_header = self.create_edgegrid_header(timestamp, nonce)
        
        test_case = TestCase(
            name='Valid EdgeGrid authentication',
            auth_header=auth_header,
            expected_status=200,
            expected_error=False
        )
        run_auth_test(test_case, self.auth, self)

    def test_invalid_edgegrid_auth(self):
        # Create an invalid EdgeGrid authentication header
        invalid_header = f'EG1-HMAC-SHA256 client_token={self.client_token};access_token={self.access_token};timestamp=20230101T00:00:00+0000;nonce=test_nonce;signature=invalid_signature'
        test_case = TestCase(
            name='Invalid EdgeGrid authentication',
            auth_header=invalid_header,
            expected_status=401,
            expected_error=True
        )
        run_auth_test(test_case, self.auth, self)

    def test_missing_edgegrid_header(self):
        test_case = TestCase(
            name='Missing EdgeGrid header',
            auth_header=None,
            expected_status=401,
            expected_error=True
        )
        run_auth_test(test_case, self.auth, self)

    def test_malformed_edgegrid_header(self):
        test_case = TestCase(
            name='Malformed EdgeGrid header',
            auth_header='EG1-HMAC-SHA256',
            expected_status=401,
            expected_error=True
        )
        run_auth_test(test_case, self.auth, self)

    def test_expired_timestamp(self):
        # Create an EdgeGrid header with expired timestamp
        expired_timestamp = time.strftime('%Y%m%dT%H:%M:%S+0000', time.gmtime(time.time() - 3600))
        expired_header = self.create_edgegrid_header(expired_timestamp, 'test_nonce')
        test_case = TestCase(
            name='Expired timestamp',
            auth_header=expired_header,
            expected_status=401,
            expected_error=True
        )
        run_auth_test(test_case, self.auth, self)

    def test_get_type(self):
        self.assertEqual(self.auth.get_type(), 'edgegrid')

if __name__ == '__main__':
    unittest.main() 