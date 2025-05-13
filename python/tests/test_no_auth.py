import unittest
from src.no_auth.no_auth import NoAuth
from tests.test_utils import TestCase, run_auth_test

class TestNoAuth(unittest.TestCase):
    def setUp(self):
        self.auth = NoAuth()

    def test_no_auth_request(self):
        test_case = TestCase(
            name='No authentication request',
            auth_header=None,
            expected_status=200,
            expected_error=False
        )
        run_auth_test(test_case, self.auth, self)

    def test_with_auth_header(self):
        test_case = TestCase(
            name='Request with auth header',
            auth_header='Bearer token',
            expected_status=200,
            expected_error=False
        )
        run_auth_test(test_case, self.auth, self)

    def test_get_type(self):
        self.assertEqual(self.auth.get_type(), 'none')

if __name__ == '__main__':
    unittest.main() 