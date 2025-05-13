import requests
import json
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
import threading
import base64
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, List, Optional, Any, Union, Tuple

class SAMLClient:
    """SAML client for authentication."""
    
    def __init__(self, entity_id: str, acs_url: str, idp_sso_url: str) -> None:
        """Initialize SAML client.
        
        Args:
            entity_id: The entity identifier.
            acs_url: The Assertion Consumer Service URL.
            idp_sso_url: The Identity Provider SSO URL.
        """
        self.entity_id = entity_id
        self.acs_url = acs_url
        self.idp_sso_url = idp_sso_url
        self.assertion: Optional[str] = None
        self.subject: Optional[str] = None

    def start_authentication(self, relay_state: Optional[str] = None) -> None:
        """Start SAML authentication flow.
        
        Args:
            relay_state: Optional relay state.
        """
        # Start local server to receive callback
        server = self._start_callback_server()
        
        # Generate and encode authentication request
        auth_request = self._generate_auth_request(relay_state)
        
        # Build SSO URL
        sso_url = f"{self.idp_sso_url}?SAMLRequest={auth_request}"
        if relay_state:
            sso_url += f"&RelayState={relay_state}"
        
        # Open browser for authentication
        webbrowser.open(sso_url)

        # Wait for callback
        server.serve_forever()

    def _start_callback_server(self) -> HTTPServer:
        """Start local server to receive SAML callback.
        
        Returns:
            HTTPServer: The callback server.
        """
        class CallbackHandler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                # Parse callback URL
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length).decode('utf-8')
                params = parse_qs(post_data)
                
                saml_response = params.get('SAMLResponse', [None])[0]
                relay_state = params.get('RelayState', [None])[0]

                if saml_response:
                    # Process SAML response
                    self.server.saml_client._handle_saml_response(saml_response)
                    
                    # Send success response
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    self.wfile.write(b"Authentication successful! You can close this window.")
                else:
                    # Send error response
                    self.send_response(400)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    self.wfile.write(b"Authentication failed!")

                # Stop server
                threading.Thread(target=self.server.shutdown).start()

        # Create server
        server = HTTPServer(('localhost', 5014), CallbackHandler)
        server.saml_client = self
        return server

    def _generate_auth_request(self, relay_state: Optional[str] = None) -> str:
        """Generate SAML authentication request.
        
        Args:
            relay_state: Optional relay state.
            
        Returns:
            str: The generated SAML authentication request.
        """
        # Create request XML
        root = ET.Element('{urn:oasis:names:tc:SAML:2.0:protocol}AuthnRequest',
                         {'ID': f"_{datetime.utcnow().timestamp()}",
                          'Version': '2.0',
                          'IssueInstant': datetime.utcnow().isoformat(),
                          'ProtocolBinding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
                          'AssertionConsumerServiceURL': self.acs_url})
        
        # Add issuer
        issuer = ET.SubElement(root, '{urn:oasis:names:tc:SAML:2.0:assertion}Issuer')
        issuer.text = self.entity_id

        # Convert to base64
        request_xml = ET.tostring(root, encoding='utf-8')
        return base64.b64encode(request_xml).decode('utf-8')

    def _handle_saml_response(self, saml_response: str) -> None:
        """Handle SAML response.
        
        Args:
            saml_response: The SAML response to handle.
        """
        try:
            # Decode and parse response
            response_xml = base64.b64decode(saml_response).decode('utf-8')
            root = ET.fromstring(response_xml)
            
            # Extract subject
            ns = {'saml': 'urn:oasis:names:tc:SAML:2.0:assertion'}
            name_id = root.find('.//saml:NameID', ns)
            if name_id is not None:
                self.subject = name_id.text
            
            # Store assertion
            self.assertion = saml_response

        except Exception as e:
            print(f"Error handling SAML response: {str(e)}")
            raise

    def call_secure_endpoint(self, url: str, method: str = 'GET', data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Call secure endpoint with SAML authentication.
        
        Args:
            url: The endpoint URL.
            method: The HTTP method.
            data: Optional request data.
            
        Returns:
            Dict[str, Any]: The endpoint response.
        """
        if not self.assertion:
            raise ValueError("Not authenticated. Call start_authentication() first.")

        headers = {
            'Authorization': f'SAML {self.assertion}',
            'Content-Type': 'application/json'
        }

        if method.upper() == 'GET':
            response = requests.get(url, headers=headers)
        else:
            response = requests.post(url, headers=headers, json=data)

        return response.json()

def main() -> None:
    """Example usage of SAML client."""
    # Create SAML client
    client = SAMLClient(
        entity_id='http://localhost:5014/sp',
        acs_url='http://localhost:5014/saml/acs',
        idp_sso_url='http://localhost:5014/saml/sso'
    )

    # Start authentication flow
    client.start_authentication(relay_state='http://localhost:5014/api/secure')

    # Test secure endpoint
    response = client.call_secure_endpoint('http://localhost:5014/api/secure')
    print('GET Response:', json.dumps(response, indent=2))

    # Test POST request
    post_data = {'message': 'Hello from SAML client!'}
    response = client.call_secure_endpoint(
        'http://localhost:5014/api/secure',
        method='POST',
        data=post_data
    )
    print('POST Response:', json.dumps(response, indent=2))

if __name__ == '__main__':
    main() 