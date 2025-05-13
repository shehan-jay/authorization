import unittest
from src.bearer_token.bearer_token import BearerToken
from tests.test_utils import TestCase, run_auth_test

class TestBearerToken(unittest.TestCase):
    def setUp(self):
        self.auth = BearerToken('valid_token')

    def test_valid_token(self):
        test_case = TestCase(
            name='Valid token',
            auth_header='Bearer valid_token',
            expected_status=200,
            expected_error=False
        )
        run_auth_test(test_case, self.auth, self)

    def test_invalid_token(self):
        test_case = TestCase(
            name='Invalid token',
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
        self.assertEqual(self.auth.get_type(), 'bearer')

if __name__ == '__main__':
    unittest.main() 