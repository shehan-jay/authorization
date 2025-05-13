import unittest
import time
import base64
from src.saml.saml import SAML
from tests.test_utils import TestCase, run_auth_test

class TestSAML(unittest.TestCase):
    def setUp(self):
        self.entity_id = 'test_entity_id'
        self.assertion_consumer_service_url = 'https://test-sp.com/acs'
        self.idp_sso_url = 'https://test-idp.com/sso'
        self.idp_certificate = 'test_certificate'
        self.auth = SAML(
            entity_id=self.entity_id,
            assertion_consumer_service_url=self.assertion_consumer_service_url,
            idp_sso_url=self.idp_sso_url,
            idp_certificate=self.idp_certificate
        )

    def create_saml_response(self, valid=True):
        """Create a SAML response."""
        if valid:
            # Create a valid SAML response
            saml_response = f"""
            <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                          ID="test_response_id"
                          Version="2.0"
                          IssueInstant="{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}"
                          Destination="{self.assertion_consumer_service_url}">
                <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                              ID="test_assertion_id"
                              Version="2.0"
                              IssueInstant="{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}">
                    <saml:Issuer>{self.idp_sso_url}</saml:Issuer>
                    <saml:Subject>
                        <saml:NameID>test_user</saml:NameID>
                    </saml:Subject>
                </saml:Assertion>
            </samlp:Response>
            """
        else:
            # Create an invalid SAML response
            saml_response = "<samlp:Response>Invalid Response</samlp:Response>"
        
        return base64.b64encode(saml_response.encode()).decode()

    def test_valid_saml_response(self):
        # Create a valid SAML response
        valid_response = self.create_saml_response(valid=True)
        test_case = TestCase(
            name='Valid SAML response',
            auth_header=f'SAML {valid_response}',
            expected_status=200,
            expected_error=False
        )
        run_auth_test(test_case, self.auth, self)

    def test_invalid_saml_response(self):
        # Create an invalid SAML response
        invalid_response = self.create_saml_response(valid=False)
        test_case = TestCase(
            name='Invalid SAML response',
            auth_header=f'SAML {invalid_response}',
            expected_status=401,
            expected_error=True
        )
        run_auth_test(test_case, self.auth, self)

    def test_missing_saml_response(self):
        test_case = TestCase(
            name='Missing SAML response',
            auth_header=None,
            expected_status=401,
            expected_error=True
        )
        run_auth_test(test_case, self.auth, self)

    def test_malformed_saml_header(self):
        test_case = TestCase(
            name='Malformed SAML header',
            auth_header='SAML',
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

    def test_expired_saml_response(self):
        # Create an expired SAML response
        expired_response = f"""
        <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                      ID="test_response_id"
                      Version="2.0"
                      IssueInstant="{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time() - 3600))}"
                      Destination="{self.assertion_consumer_service_url}">
            <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                          ID="test_assertion_id"
                          Version="2.0"
                          IssueInstant="{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time() - 3600))}">
                <saml:Issuer>{self.idp_sso_url}</saml:Issuer>
                <saml:Subject>
                    <saml:NameID>test_user</saml:NameID>
                </saml:Subject>
            </saml:Assertion>
        </samlp:Response>
        """
        expired_response_b64 = base64.b64encode(expired_response.encode()).decode()
        test_case = TestCase(
            name='Expired SAML response',
            auth_header=f'SAML {expired_response_b64}',
            expected_status=401,
            expected_error=True
        )
        run_auth_test(test_case, self.auth, self)

    def test_get_type(self):
        self.assertEqual(self.auth.get_type(), 'saml')

if __name__ == '__main__':
    unittest.main() 