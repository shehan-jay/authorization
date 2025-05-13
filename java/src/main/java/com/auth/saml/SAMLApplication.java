package com.auth.saml;

import com.auth.base.BaseAuth;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.ResponseEntity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Base64;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.io.ByteArrayInputStream;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.StringWriter;

/**
 * Spring Boot application implementing SAML authentication.
 */
@SpringBootApplication
public class SAMLApplication {
    public static void main(String[] args) {
        SpringApplication.run(SAMLApplication.class, args);
    }

    /**
     * Security configuration for SAML authentication.
     */
    @Configuration
    @EnableWebSecurity
    public static class SecurityConfig extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/saml/**").permitAll()
                .antMatchers("/api/secure/**").authenticated()
                .anyRequest().permitAll()
                .and()
                .addFilterBefore(samlAuthFilter(), UsernamePasswordAuthenticationFilter.class);
        }

        @Bean
        public SAMLAuthFilter samlAuthFilter() {
            return new SAMLAuthFilter();
        }
    }

    /**
     * SAML authentication implementation.
     */
    public static class SAMLAuth extends BaseAuth {
        private final Map<String, SAMLAssertion> assertions = new ConcurrentHashMap<>();
        private final Map<String, SAMLAuthRequest> authRequests = new ConcurrentHashMap<>();
        private final KeyPair keyPair;
        private final String idpEntityId;
        private final String spEntityId;

        /**
         * Initialize SAML authentication with key pair and entity IDs.
         * @throws Exception if key pair generation fails
         */
        public SAMLAuth() throws Exception {
            // Generate key pair for signing
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            this.keyPair = generator.generateKeyPair();

            // Set entity IDs
            this.idpEntityId = "http://localhost:5014/idp";
            this.spEntityId = "http://localhost:5014/sp";
        }

        /**
         * Authenticate a request using SAML assertion.
         * @param request HTTP request to authenticate
         * @return true if authentication succeeds, false otherwise
         */
        @Override
        public boolean authenticate(HttpServletRequest request) {
            String authHeader = request.getHeader("Authorization");
            if (authHeader == null || !authHeader.startsWith("SAML ")) {
                return false;
            }

            try {
                // Extract assertion
                String assertion = authHeader.substring(6);
                String assertionXml = new String(Base64.getDecoder().decode(assertion));

                // Parse and validate assertion
                DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
                factory.setNamespaceAware(true);
                DocumentBuilder builder = factory.newDocumentBuilder();
                Document doc = builder.parse(new ByteArrayInputStream(assertionXml.getBytes()));

                // Extract assertion ID
                String assertionId = doc.getDocumentElement().getAttribute("ID");
                if (!assertions.containsKey(assertionId)) {
                    return false;
                }

                // Check expiration
                SAMLAssertion samlAssertion = assertions.get(assertionId);
                if (samlAssertion.expiresAt.before(new Date())) {
                    return false;
                }

                // Store assertion info in request
                request.setAttribute("assertion", samlAssertion);
                return true;

            } catch (Exception e) {
                e.printStackTrace();
                return false;
            }
        }

        /**
         * Generate a SAML assertion.
         * @param subject Subject identifier
         * @param audience Audience identifier
         * @return Base64 encoded SAML assertion
         * @throws Exception if assertion generation fails
         */
        public String generateAssertion(String subject, String audience) throws Exception {
            String assertionId = "_" + UUID.randomUUID().toString();
            Date now = new Date();
            Date expiresAt = new Date(now.getTime() + 3600 * 1000); // 1 hour

            // Create assertion XML
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.newDocument();

            Element assertion = doc.createElementNS("urn:oasis:names:tc:SAML:2.0:assertion", "saml:Assertion");
            assertion.setAttribute("ID", assertionId);
            assertion.setAttribute("IssueInstant", new Date().toInstant().toString());
            assertion.setAttribute("Version", "2.0");
            doc.appendChild(assertion);

            // Add issuer
            Element issuer = doc.createElementNS("urn:oasis:names:tc:SAML:2.0:assertion", "saml:Issuer");
            issuer.setTextContent(idpEntityId);
            assertion.appendChild(issuer);

            // Add subject
            Element subjectElem = doc.createElementNS("urn:oasis:names:tc:SAML:2.0:assertion", "saml:Subject");
            Element nameId = doc.createElementNS("urn:oasis:names:tc:SAML:2.0:assertion", "saml:NameID");
            nameId.setTextContent(subject);
            subjectElem.appendChild(nameId);
            assertion.appendChild(subjectElem);

            // Add conditions
            Element conditions = doc.createElementNS("urn:oasis:names:tc:SAML:2.0:assertion", "saml:Conditions");
            conditions.setAttribute("NotBefore", now.toInstant().toString());
            conditions.setAttribute("NotOnOrAfter", expiresAt.toInstant().toString());
            Element audienceRestriction = doc.createElementNS("urn:oasis:names:tc:SAML:2.0:assertion", "saml:AudienceRestriction");
            Element audienceElem = doc.createElementNS("urn:oasis:names:tc:SAML:2.0:assertion", "saml:Audience");
            audienceElem.setTextContent(audience);
            audienceRestriction.appendChild(audienceElem);
            conditions.appendChild(audienceRestriction);
            assertion.appendChild(conditions);

            // Store assertion
            assertions.put(assertionId, new SAMLAssertion(subject, audience, expiresAt));

            // Convert to base64
            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            Transformer transformer = transformerFactory.newTransformer();
            StringWriter writer = new StringWriter();
            transformer.transform(new DOMSource(doc), new StreamResult(writer));
            return Base64.getEncoder().encodeToString(writer.toString().getBytes());
        }

        /**
         * Generate a SAML authentication request.
         * @param issuer Issuer identifier
         * @param acsUrl Assertion Consumer Service URL
         * @param relayState Relay state
         * @return Base64 encoded SAML authentication request
         * @throws Exception if request generation fails
         */
        public String generateAuthRequest(String issuer, String acsUrl, String relayState) throws Exception {
            String requestId = "_" + UUID.randomUUID().toString();

            // Create request XML
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.newDocument();

            Element authnRequest = doc.createElementNS("urn:oasis:names:tc:SAML:2.0:protocol", "samlp:AuthnRequest");
            authnRequest.setAttribute("ID", requestId);
            authnRequest.setAttribute("Version", "2.0");
            authnRequest.setAttribute("IssueInstant", new Date().toInstant().toString());
            authnRequest.setAttribute("ProtocolBinding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
            authnRequest.setAttribute("AssertionConsumerServiceURL", acsUrl);
            doc.appendChild(authnRequest);

            // Add issuer
            Element issuerElem = doc.createElementNS("urn:oasis:names:tc:SAML:2.0:assertion", "saml:Issuer");
            issuerElem.setTextContent(issuer);
            authnRequest.appendChild(issuerElem);

            // Store request
            authRequests.put(requestId, new SAMLAuthRequest(issuer, acsUrl, relayState));

            // Convert to base64
            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            Transformer transformer = transformerFactory.newTransformer();
            StringWriter writer = new StringWriter();
            transformer.transform(new DOMSource(doc), new StreamResult(writer));
            return Base64.getEncoder().encodeToString(writer.toString().getBytes());
        }
    }

    /**
     * SAML assertion data.
     */
    public static class SAMLAssertion {
        public final String subject;
        public final String audience;
        public final Date expiresAt;

        /**
         * Create a new SAML assertion.
         * @param subject Subject identifier
         * @param audience Audience identifier
         * @param expiresAt Expiration time
         */
        public SAMLAssertion(String subject, String audience, Date expiresAt) {
            this.subject = subject;
            this.audience = audience;
            this.expiresAt = expiresAt;
        }
    }

    /**
     * SAML authentication request data.
     */
    public static class SAMLAuthRequest {
        public final String issuer;
        public final String acsUrl;
        public final String relayState;

        /**
         * Create a new SAML authentication request.
         * @param issuer Issuer identifier
         * @param acsUrl Assertion Consumer Service URL
         * @param relayState Relay state
         */
        public SAMLAuthRequest(String issuer, String acsUrl, String relayState) {
            this.issuer = issuer;
            this.acsUrl = acsUrl;
            this.relayState = relayState;
        }
    }

    /**
     * SAML authentication filter.
     */
    public static class SAMLAuthFilter extends OncePerRequestFilter {
        private final SAMLAuth auth;

        /**
         * Initialize SAML authentication filter.
         */
        public SAMLAuthFilter() {
            try {
                this.auth = new SAMLAuth();
            } catch (Exception e) {
                throw new RuntimeException("Failed to initialize SAML auth", e);
            }
        }

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws ServletException, IOException {
            if (!auth.authenticate(request)) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("Invalid SAML authentication");
                return;
            }
            chain.doFilter(request, response);
        }
    }

    /**
     * SAML controller for handling SAML endpoints.
     */
    @RestController
    @RequestMapping("/saml")
    public static class SAMLController {
        private final SAMLAuth auth;

        /**
         * Initialize SAML controller.
         */
        public SAMLController() {
            try {
                this.auth = new SAMLAuth();
            } catch (Exception e) {
                throw new RuntimeException("Failed to initialize SAML auth", e);
            }
        }

        /**
         * Get SAML metadata.
         * @return SAML metadata
         */
        @GetMapping("/metadata")
        public ResponseEntity<Map<String, Object>> metadata() {
            Map<String, Object> response = new HashMap<>();
            response.put("idp", Map.of(
                "entity_id", auth.idpEntityId,
                "sso_url", "http://localhost:5014/saml/sso"
            ));
            response.put("sp", Map.of(
                "entity_id", auth.spEntityId,
                "acs_url", "http://localhost:5014/saml/acs"
            ));
            return ResponseEntity.ok(response);
        }

        /**
         * Handle SAML SSO request.
         * @param SAMLRequest SAML request
         * @param RelayState Relay state
         * @return SAML response
         */
        @GetMapping("/sso")
        public ResponseEntity<?> sso(
                @RequestParam String SAMLRequest,
                @RequestParam(required = false) String RelayState) {
            try {
                // Decode and parse request
                String requestXml = new String(Base64.getDecoder().decode(SAMLRequest));
                DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
                factory.setNamespaceAware(true);
                DocumentBuilder builder = factory.newDocumentBuilder();
                Document doc = builder.parse(new ByteArrayInputStream(requestXml.getBytes()));

                // Extract request ID
                String requestId = doc.getDocumentElement().getAttribute("ID");
                if (!auth.authRequests.containsKey(requestId)) {
                    return ResponseEntity.badRequest().body(Map.of("error", "Invalid request ID"));
                }

                // Get request details
                SAMLAuthRequest request = auth.authRequests.get(requestId);

                // For demonstration, we'll auto-authenticate the user
                String assertion = auth.generateAssertion("user123", request.issuer);

                // Redirect to ACS URL with assertion
                String redirectUrl = request.acsUrl + "?SAMLResponse=" + assertion;
                if (request.relayState != null) {
                    redirectUrl += "&RelayState=" + request.relayState;
                }
                return ResponseEntity.status(HttpServletResponse.SC_FOUND)
                    .header("Location", redirectUrl)
                    .build();

            } catch (Exception e) {
                return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
            }
        }

        /**
         * Handle SAML ACS request.
         * @param SAMLResponse SAML response
         * @param RelayState Relay state
         * @return Redirect response
         */
        @PostMapping("/acs")
        public ResponseEntity<?> acs(
                @RequestParam String SAMLResponse,
                @RequestParam(required = false) String RelayState) {
            try {
                // Decode and parse response
                String responseXml = new String(Base64.getDecoder().decode(SAMLResponse));
                DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
                factory.setNamespaceAware(true);
                DocumentBuilder builder = factory.newDocumentBuilder();
                Document doc = builder.parse(new ByteArrayInputStream(responseXml.getBytes()));

                // Extract assertion ID
                String assertionId = doc.getDocumentElement().getAttribute("ID");
                if (!auth.assertions.containsKey(assertionId)) {
                    return ResponseEntity.badRequest().body(Map.of("error", "Invalid assertion ID"));
                }

                // Get assertion details
                SAMLAssertion assertion = auth.assertions.get(assertionId);

                // Redirect to relay state if provided
                if (RelayState != null) {
                    return ResponseEntity.status(HttpServletResponse.SC_FOUND)
                        .header("Location", RelayState)
                        .build();
                }
                return ResponseEntity.ok(Map.of("message", "Authentication successful"));

            } catch (Exception e) {
                return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
            }
        }
    }

    /**
     * Secure controller for protected endpoints.
     */
    @RestController
    @RequestMapping("/api")
    public static class SecureController {
        /**
         * Handle secure GET request.
         * @param request HTTP request
         * @return Response data
         */
        @GetMapping("/secure")
        public ResponseEntity<Map<String, Object>> secureGet(HttpServletRequest request) {
            SAMLAssertion assertion = (SAMLAssertion) request.getAttribute("assertion");
            Map<String, Object> response = new HashMap<>();
            response.put("message", "This is a secure endpoint that requires SAML authentication");
            response.put("status", "success");
            response.put("assertion", assertion);

            return ResponseEntity.ok(response);
        }

        /**
         * Handle secure POST request.
         * @param request HTTP request
         * @param body Request body
         * @return Response data
         */
        @PostMapping("/secure")
        public ResponseEntity<Map<String, Object>> securePost(
                HttpServletRequest request,
                @RequestBody(required = false) Map<String, Object> body) {
            SAMLAssertion assertion = (SAMLAssertion) request.getAttribute("assertion");
            Map<String, Object> response = new HashMap<>();
            response.put("message", "This is a secure endpoint that requires SAML authentication");
            response.put("status", "success");
            response.put("assertion", assertion);
            response.put("received_data", body);

            return ResponseEntity.ok(response);
        }
    }
} 