from flask import Flask, jsonify, request, redirect, url_for, session
from base_auth import BaseAuth
import xml.etree.ElementTree as ET
import base64
import hashlib
import time
import secrets
from datetime import datetime, timedelta
import uuid
from typing import Dict, List, Optional, Any, Union, Tuple, cast

class SAMLAuth(BaseAuth):
    """SAML authentication handler."""
    
    def __init__(self) -> None:
        """Initialize SAML authentication handler."""
        super().__init__()
        self.port = 5014
        # In-memory storage for SAML data (for demonstration)
        self.idp_metadata: Dict[str, str] = {
            'entity_id': 'http://localhost:5014/idp',
            'sso_url': 'http://localhost:5014/saml/sso',
            'certificate': self._generate_certificate()
        }
        self.sp_metadata: Dict[str, str] = {
            'entity_id': 'http://localhost:5014/sp',
            'acs_url': 'http://localhost:5014/saml/acs',
            'certificate': self._generate_certificate()
        }
        self.assertions: Dict[str, Tuple[str, str, float]] = {}  # assertion_id -> (subject, audience, expires_at)
        self.auth_requests: Dict[str, Tuple[str, str, Optional[str]]] = {}  # request_id -> (issuer, acs_url, relay_state)

    def _generate_certificate(self) -> str:
        """Generate a self-signed certificate for demonstration.
        
        Returns:
            str: The generated certificate.
        """
        return f"-----BEGIN CERTIFICATE-----\n{secrets.token_hex(32)}\n-----END CERTIFICATE-----"

    def authenticate(self, request: Any) -> bool:
        """Authenticate the request using SAML.
        
        Args:
            request: The request object to authenticate.
            
        Returns:
            bool: True if authentication is successful, False otherwise.
        """
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('SAML '):
            return False

        try:
            # Extract assertion
            assertion = auth_header.split(' ')[1]
            assertion_xml = base64.b64decode(assertion).decode('utf-8')
            
            # Parse and validate assertion
            root = ET.fromstring(assertion_xml)
            ns = {'saml': 'urn:oasis:names:tc:SAML:2.0:assertion'}
            
            # Extract assertion ID
            assertion_id = root.get('ID')
            if assertion_id not in self.assertions:
                return False
            
            # Check expiration
            subject, audience, expires_at = self.assertions[assertion_id]
            if expires_at < time.time():
                return False
            
            # Store assertion info in request context
            request.assertion_info = {
                'subject': subject,
                'audience': audience,
                'expires_at': expires_at
            }
            return True

        except Exception as e:
            print(f"Authentication error: {str(e)}")
            return False

    def generate_assertion(self, subject: str, audience: str) -> str:
        """Generate a SAML assertion.
        
        Args:
            subject: The subject identifier.
            audience: The audience identifier.
            
        Returns:
            str: The generated SAML assertion.
        """
        assertion_id = f"_{uuid.uuid4()}"
        expires_at = time.time() + 3600  # 1 hour

        # Create assertion XML
        root = ET.Element('{urn:oasis:names:tc:SAML:2.0:assertion}Assertion',
                         {'ID': assertion_id,
                          'IssueInstant': datetime.utcnow().isoformat(),
                          'Version': '2.0'})
        
        # Add issuer
        issuer = ET.SubElement(root, '{urn:oasis:names:tc:SAML:2.0:assertion}Issuer')
        issuer.text = self.idp_metadata['entity_id']
        
        # Add subject
        subject_elem = ET.SubElement(root, '{urn:oasis:names:tc:SAML:2.0:assertion}Subject')
        name_id = ET.SubElement(subject_elem, '{urn:oasis:names:tc:SAML:2.0:assertion}NameID')
        name_id.text = subject
        
        # Add conditions
        conditions = ET.SubElement(root, '{urn:oasis:names:tc:SAML:2.0:assertion}Conditions',
                                 {'NotBefore': datetime.utcnow().isoformat(),
                                  'NotOnOrAfter': datetime.fromtimestamp(expires_at).isoformat()})
        audience_restriction = ET.SubElement(conditions, '{urn:oasis:names:tc:SAML:2.0:assertion}AudienceRestriction')
        audience_elem = ET.SubElement(audience_restriction, '{urn:oasis:names:tc:SAML:2.0:assertion}Audience')
        audience_elem.text = audience

        # Store assertion
        self.assertions[assertion_id] = (subject, audience, expires_at)

        # Convert to base64
        assertion_xml = ET.tostring(root, encoding='utf-8')
        return base64.b64encode(assertion_xml).decode('utf-8')

    def generate_auth_request(self, issuer: str, acs_url: str, relay_state: Optional[str] = None) -> str:
        """Generate a SAML authentication request.
        
        Args:
            issuer: The issuer identifier.
            acs_url: The Assertion Consumer Service URL.
            relay_state: Optional relay state.
            
        Returns:
            str: The generated SAML authentication request.
        """
        request_id = f"_{uuid.uuid4()}"
        
        # Create request XML
        root = ET.Element('{urn:oasis:names:tc:SAML:2.0:protocol}AuthnRequest',
                         {'ID': request_id,
                          'Version': '2.0',
                          'IssueInstant': datetime.utcnow().isoformat(),
                          'ProtocolBinding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
                          'AssertionConsumerServiceURL': acs_url})
        
        # Add issuer
        issuer_elem = ET.SubElement(root, '{urn:oasis:names:tc:SAML:2.0:assertion}Issuer')
        issuer_elem.text = issuer

        # Store request
        self.auth_requests[request_id] = (issuer, acs_url, relay_state)

        # Convert to base64
        request_xml = ET.tostring(root, encoding='utf-8')
        return base64.b64encode(request_xml).decode('utf-8')

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
auth = SAMLAuth()

@app.route('/saml/metadata', methods=['GET'])
def metadata() -> Dict[str, Dict[str, str]]:
    """SAML metadata endpoint.
    
    Returns:
        Dict[str, Dict[str, str]]: The SAML metadata.
    """
    return jsonify({
        'idp': auth.idp_metadata,
        'sp': auth.sp_metadata
    })

@app.route('/saml/sso', methods=['GET'])
def sso() -> Union[Dict[str, str], str]:
    """SAML SSO endpoint.
    
    Returns:
        Union[Dict[str, str], str]: The SSO response or error.
    """
    # Get request parameters
    saml_request = request.args.get('SAMLRequest')
    relay_state = request.args.get('RelayState')

    if not saml_request:
        return jsonify({'error': 'Missing SAMLRequest parameter'}), 400

    try:
        # Decode and parse request
        request_xml = base64.b64decode(saml_request).decode('utf-8')
        root = ET.fromstring(request_xml)
        
        # Extract request ID
        request_id = root.get('ID')
        if request_id not in auth.auth_requests:
            return jsonify({'error': 'Invalid request ID'}), 400
        
        # Get request details
        issuer, acs_url, _ = auth.auth_requests[request_id]
        
        # For demonstration, we'll auto-authenticate the user
        assertion = auth.generate_assertion('user123', issuer)
        
        # Redirect to ACS URL with assertion
        return redirect(f"{acs_url}?SAMLResponse={assertion}&RelayState={relay_state}")

    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/saml/acs', methods=['POST'])
def acs() -> Union[Dict[str, str], str]:
    """SAML Assertion Consumer Service endpoint.
    
    Returns:
        Union[Dict[str, str], str]: The ACS response or error.
    """
    # Get response parameters
    saml_response = request.form.get('SAMLResponse')
    relay_state = request.form.get('RelayState')

    if not saml_response:
        return jsonify({'error': 'Missing SAMLResponse parameter'}), 400

    try:
        # Decode and parse response
        response_xml = base64.b64decode(saml_response).decode('utf-8')
        root = ET.fromstring(response_xml)
        
        # Extract assertion ID
        assertion_id = root.get('ID')
        if assertion_id not in auth.assertions:
            return jsonify({'error': 'Invalid assertion ID'}), 400
        
        # Get assertion details
        subject, audience, expires_at = auth.assertions[assertion_id]
        
        # Store assertion in session
        session['saml_assertion'] = saml_response
        session['saml_subject'] = subject
        
        # Redirect to relay state if provided
        if relay_state:
            return redirect(relay_state)
        return jsonify({'message': 'Authentication successful'})

    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/secure', methods=['GET', 'POST'])
@auth.requires_auth
def secure_endpoint() -> Dict[str, Any]:
    """Secure endpoint that requires SAML authentication.
    
    Returns:
        Dict[str, Any]: The endpoint response.
    """
    if request.method == 'GET':
        return jsonify({
            'message': 'Hello from secure endpoint!',
            'subject': request.assertion_info['subject']
        })
    else:
        return jsonify({
            'message': 'Received POST request',
            'subject': request.assertion_info['subject'],
            'body': request.get_json()
        })

if __name__ == '__main__':
    app.run(port=auth.port) 