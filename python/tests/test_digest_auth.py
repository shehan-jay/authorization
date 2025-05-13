import unittest
import hashlib
from src.digest_auth.digest_auth import DigestAuth
from tests.test_utils import TestCase, run_auth_test

class TestDigestAuth(unittest.TestCase):
    def setUp(self):
        self.username = 'test_user'
        self.password = 'test_password'
        self.realm = 'test_realm'
        self.auth = DigestAuth(
            username=self.username,
            password=self.password,
            realm=self.realm
        )

    def create_digest_header(self, nonce, nc, cnonce, qop='auth'):
        """Create a Digest authentication header."""
        ha1 = hashlib.md5(f'{self.username}:{self.realm}:{self.password}'.encode()).hexdigest()
        ha2 = hashlib.md5('GET:/'.encode()).hexdigest()
        response = hashlib.md5(f'{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}'.encode()).hexdigest()
        
        return f'Digest username="{self.username}", realm="{self.realm}", nonce="{nonce}", uri="/", algorithm=MD5, response="{response}", qop={qop}, nc={nc}, cnonce="{cnonce}"'

    def test_valid_digest_auth(self):
        nonce = 'test_nonce'
        nc = '00000001'
        cnonce = 'test_cnonce'
        auth_header = self.create_digest_header(nonce, nc, cnonce)
        
        test_case = TestCase(
            name='Valid Digest authentication',
            auth_header=auth_header,
            expected_status=200,
            expected_error=False
        )
        run_auth_test(test_case, self.auth, self)

    def test_invalid_digest_auth(self):
        # Create an invalid digest header with wrong response
        invalid_header = f'Digest username="{self.username}", realm="{self.realm}", nonce="test_nonce", uri="/", algorithm=MD5, response="invalid_response", qop=auth, nc=00000001, cnonce="test_cnonce"'
        
        test_case = TestCase(
            name='Invalid Digest authentication',
            auth_header=invalid_header,
            expected_status=401,
            expected_error=True
        )
        run_auth_test(test_case, self.auth, self)

    def test_missing_digest_header(self):
        test_case = TestCase(
            name='Missing Digest header',
            auth_header=None,
            expected_status=401,
            expected_error=True
        )
        run_auth_test(test_case, self.auth, self)

    def test_malformed_digest_header(self):
        test_case = TestCase(
            name='Malformed Digest header',
            auth_header='Digest',
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
        self.assertEqual(self.auth.get_type(), 'digest')

if __name__ == '__main__':
    unittest.main() 