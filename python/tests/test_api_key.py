import unittest
from src.api_key.api_key import APIKey
from tests.test_utils import TestCase, run_auth_test

class TestAPIKey(unittest.TestCase):
    def setUp(self):
        self.auth = APIKey('valid_api_key')

    def test_valid_api_key_in_header(self):
        test_case = TestCase(
            name='Valid API key in header',
            auth_header='valid_api_key',
            expected_status=200,
            expected_error=False
        )
        run_auth_test(test_case, self.auth, self)

    def test_valid_api_key_in_query(self):
        test_case = TestCase(
            name='Valid API key in query',
            query_params={'api_key': 'valid_api_key'},
            expected_status=200,
            expected_error=False
        )
        run_auth_test(test_case, self.auth, self)

    def test_invalid_api_key(self):
        test_case = TestCase(
            name='Invalid API key',
            auth_header='invalid_api_key',
            expected_status=401,
            expected_error=True
        )
        run_auth_test(test_case, self.auth, self)

    def test_missing_api_key(self):
        test_case = TestCase(
            name='Missing API key',
            auth_header=None,
            expected_status=401,
            expected_error=True
        )
        run_auth_test(test_case, self.auth, self)

    def test_get_type(self):
        self.assertEqual(self.auth.get_type(), 'apikey')

if __name__ == '__main__':
    unittest.main() 