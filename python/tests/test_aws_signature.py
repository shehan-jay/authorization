import unittest
import time
from src.aws_signature.aws_signature import AWSSignature
from tests.test_utils import TestCase, run_auth_test

class TestAWSSignature(unittest.TestCase):
    def setUp(self):
        self.access_key = 'test_access_key'
        self.secret_key = 'test_secret_key'
        self.region = 'us-east-1'
        self.service = 's3'
        self.auth = AWSSignature(
            access_key=self.access_key,
            secret_key=self.secret_key,
            region=self.region,
            service=self.service
        )

    def test_valid_aws_signature(self):
        # Create a valid AWS signature header
        auth_header = self.auth.get_auth_header('GET', '/test-bucket/test-object')
        test_case = TestCase(
            name='Valid AWS signature',
            auth_header=auth_header,
            expected_status=200,
            expected_error=False
        )
        run_auth_test(test_case, self.auth, self)

    def test_invalid_aws_signature(self):
        # Create an invalid AWS signature header
        invalid_header = 'AWS4-HMAC-SHA256 Credential=test_access_key/20230101/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=invalid_signature'
        test_case = TestCase(
            name='Invalid AWS signature',
            auth_header=invalid_header,
            expected_status=401,
            expected_error=True
        )
        run_auth_test(test_case, self.auth, self)

    def test_missing_aws_signature(self):
        test_case = TestCase(
            name='Missing AWS signature',
            auth_header=None,
            expected_status=401,
            expected_error=True
        )
        run_auth_test(test_case, self.auth, self)

    def test_malformed_aws_signature(self):
        test_case = TestCase(
            name='Malformed AWS signature',
            auth_header='AWS4-HMAC-SHA256',
            expected_status=401,
            expected_error=True
        )
        run_auth_test(test_case, self.auth, self)

    def test_expired_aws_signature(self):
        # Create an expired AWS signature header
        expired_timestamp = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime(time.time() - 3600))
        expired_header = f'AWS4-HMAC-SHA256 Credential={self.access_key}/20230101/{self.region}/{self.service}/aws4_request, SignedHeaders=host;x-amz-date, Signature=test_signature, X-Amz-Date={expired_timestamp}'
        test_case = TestCase(
            name='Expired AWS signature',
            auth_header=expired_header,
            expected_status=401,
            expected_error=True
        )
        run_auth_test(test_case, self.auth, self)

    def test_get_type(self):
        self.assertEqual(self.auth.get_type(), 'aws')

if __name__ == '__main__':
    unittest.main() 