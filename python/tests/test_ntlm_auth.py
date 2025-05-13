import unittest
import base64
from src.ntlm_auth.ntlm_auth import NTLMAuth
from tests.test_utils import TestCase, run_auth_test

class TestNTLMAuth(unittest.TestCase):
    def setUp(self):
        self.username = 'test_user'
        self.password = 'test_password'
        self.domain = 'test_domain'
        self.auth = NTLMAuth(
            username=self.username,
            password=self.password,
            domain=self.domain
        )

    def test_valid_ntlm_auth(self):
        # Create a valid NTLM authentication header
        auth_header = self.auth.get_auth_header()
        test_case = TestCase(
            name='Valid NTLM authentication',
            auth_header=auth_header,
            expected_status=200,
            expected_error=False
        )
        run_auth_test(test_case, self.auth, self)

    def test_invalid_ntlm_auth(self):
        # Create an invalid NTLM authentication header
        invalid_header = 'NTLM invalid_token'
        test_case = TestCase(
            name='Invalid NTLM authentication',
            auth_header=invalid_header,
            expected_status=401,
            expected_error=True
        )
        run_auth_test(test_case, self.auth, self)

    def test_missing_ntlm_header(self):
        test_case = TestCase(
            name='Missing NTLM header',
            auth_header=None,
            expected_status=401,
            expected_error=True
        )
        run_auth_test(test_case, self.auth, self)

    def test_malformed_ntlm_header(self):
        test_case = TestCase(
            name='Malformed NTLM header',
            auth_header='NTLM',
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
        self.assertEqual(self.auth.get_type(), 'ntlm')

if __name__ == '__main__':
    unittest.main() 