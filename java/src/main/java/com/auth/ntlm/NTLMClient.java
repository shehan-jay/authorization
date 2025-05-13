package com.auth.ntlm;

import org.springframework.http.*;
import org.springframework.web.client.RestTemplate;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.stream.Collectors;

public class NTLMClient {
    private final String baseUrl;
    private final String domain;
    private final String username;
    private final String password;
    private final RestTemplate restTemplate;
    private String sessionId;
    private byte[] challenge;

    public NTLMClient(String baseUrl, String domain, String username, String password) {
        this.baseUrl = baseUrl;
        this.domain = domain;
        this.username = username;
        this.password = password;
        this.restTemplate = new RestTemplate();
    }

    private byte[] generateNTHash(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD4");
            return md.digest(password.getBytes(StandardCharsets.UTF_16LE));
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate NT hash", e);
        }
    }

    private byte[] generateLMHash(String password) {
        try {
            // Convert password to uppercase and pad to 14 bytes
            byte[] pwd = password.toUpperCase().getBytes(StandardCharsets.US_ASCII);
            byte[] padded = new byte[14];
            System.arraycopy(pwd, 0, padded, 0, Math.min(pwd.length, 14));

            // Split into two 7-byte halves
            byte[] key1 = Arrays.copyOfRange(padded, 0, 7);
            byte[] key2 = Arrays.copyOfRange(padded, 7, 14);

            // Convert each half to 8-byte DES key
            byte[] desKey1 = createDESKey(key1);
            byte[] desKey2 = createDESKey(key2);

            // Encrypt "KGS!@#$%" with each key
            Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding");
            byte[] magic = "KGS!@#$%".getBytes(StandardCharsets.US_ASCII);

            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(desKey1, "DES"));
            byte[] part1 = cipher.doFinal(magic);

            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(desKey2, "DES"));
            byte[] part2 = cipher.doFinal(magic);

            // Combine results
            byte[] result = new byte[16];
            System.arraycopy(part1, 0, result, 0, 8);
            System.arraycopy(part2, 0, result, 8, 8);
            return result;
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate LM hash", e);
        }
    }

    private byte[] createDESKey(byte[] key) {
        byte[] desKey = new byte[8];
        desKey[0] = (byte) (key[0] & 0xfe);
        desKey[1] = (byte) ((key[0] << 7) | (key[1] >> 1));
        desKey[2] = (byte) ((key[1] << 6) | (key[2] >> 2));
        desKey[3] = (byte) ((key[2] << 5) | (key[3] >> 3));
        desKey[4] = (byte) ((key[3] << 4) | (key[4] >> 4));
        desKey[5] = (byte) ((key[4] << 3) | (key[5] >> 5));
        desKey[6] = (byte) ((key[5] << 2) | (key[6] >> 6));
        desKey[7] = (byte) (key[6] << 1);

        // Set parity bits
        for (int i = 0; i < 8; i++) {
            desKey[i] |= calculateParity(desKey[i]);
        }

        return desKey;
    }

    private byte calculateParity(byte b) {
        b ^= b >> 4;
        b ^= b >> 2;
        b ^= b >> 1;
        return (byte) (b & 1);
    }

    private byte[] createType1Message() {
        ByteArrayOutputStream msg = new ByteArrayOutputStream();
        try {
            // Signature
            msg.write("NTLMSSP\0".getBytes(StandardCharsets.US_ASCII));

            // Message type (1)
            msg.write(intToBytes(1));

            // Flags
            msg.write(intToBytes(0x00008201));

            // Domain
            byte[] domainBytes = domain.getBytes(StandardCharsets.UTF_16LE);
            msg.write(shortToBytes((short) domainBytes.length));
            msg.write(shortToBytes((short) domainBytes.length));
            msg.write(intToBytes(40));

            // Workstation
            byte[] workstation = "WORKSTATION".getBytes(StandardCharsets.US_ASCII);
            msg.write(shortToBytes((short) workstation.length));
            msg.write(shortToBytes((short) workstation.length));
            msg.write(intToBytes(40 + domainBytes.length));
        } catch (Exception e) {
            throw new RuntimeException("Failed to create Type 1 message", e);
        }
        return msg.toByteArray();
    }

    private byte[] createType3Message(byte[] challenge) {
        ByteArrayOutputStream msg = new ByteArrayOutputStream();
        try {
            // Signature
            msg.write("NTLMSSP\0".getBytes(StandardCharsets.US_ASCII));

            // Message type (3)
            msg.write(intToBytes(3));

            // LM response
            byte[] lmHash = generateLMHash(password);
            byte[] lmResponse = new byte[24];
            for (int i = 0; i < 3; i++) {
                byte[] key = createDESKey(Arrays.copyOfRange(lmHash, i * 7, (i + 1) * 7));
                Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DES"));
                byte[] part = cipher.doFinal(challenge);
                System.arraycopy(part, 0, lmResponse, i * 8, 8);
            }

            msg.write(shortToBytes((short) lmResponse.length));
            msg.write(shortToBytes((short) lmResponse.length));
            msg.write(intToBytes(72));

            // NT response
            byte[] ntHash = generateNTHash(password);
            byte[] ntResponse = new byte[24];
            for (int i = 0; i < 3; i++) {
                byte[] key = createDESKey(Arrays.copyOfRange(ntHash, i * 7, (i + 1) * 7));
                Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DES"));
                byte[] part = cipher.doFinal(challenge);
                System.arraycopy(part, 0, ntResponse, i * 8, 8);
            }

            msg.write(shortToBytes((short) ntResponse.length));
            msg.write(shortToBytes((short) ntResponse.length));
            msg.write(intToBytes(96));

            // Domain
            byte[] domainBytes = domain.getBytes(StandardCharsets.UTF_16LE);
            msg.write(shortToBytes((short) domainBytes.length));
            msg.write(shortToBytes((short) domainBytes.length));
            msg.write(intToBytes(120));

            // Username
            byte[] usernameBytes = username.getBytes(StandardCharsets.UTF_16LE);
            msg.write(shortToBytes((short) usernameBytes.length));
            msg.write(shortToBytes((short) usernameBytes.length));
            msg.write(intToBytes(120 + domainBytes.length));

            // Workstation
            byte[] workstation = "WORKSTATION".getBytes(StandardCharsets.US_ASCII);
            msg.write(shortToBytes((short) workstation.length));
            msg.write(shortToBytes((short) workstation.length));
            msg.write(intToBytes(120 + domainBytes.length + usernameBytes.length));

            // Session key
            msg.write(shortToBytes((short) 0));
            msg.write(shortToBytes((short) 0));
            msg.write(intToBytes(120 + domainBytes.length + usernameBytes.length + workstation.length));

            // Flags
            msg.write(intToBytes(0x00008201));

            // Add variable data
            msg.write(lmResponse);
            msg.write(ntResponse);
            msg.write(domainBytes);
            msg.write(usernameBytes);
            msg.write(workstation);
        } catch (Exception e) {
            throw new RuntimeException("Failed to create Type 3 message", e);
        }
        return msg.toByteArray();
    }

    private byte[] intToBytes(int value) {
        return new byte[] {
            (byte) (value & 0xff),
            (byte) ((value >> 8) & 0xff),
            (byte) ((value >> 16) & 0xff),
            (byte) ((value >> 24) & 0xff)
        };
    }

    private byte[] shortToBytes(short value) {
        return new byte[] {
            (byte) (value & 0xff),
            (byte) ((value >> 8) & 0xff)
        };
    }

    public ResponseEntity<String> callSecureEndpoint(String method, Map<String, Object> body) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);

            if (challenge == null) {
                // Send Type 1 message
                byte[] type1Msg = createType1Message();
                headers.set("Authorization", "NTLM " + Base64.getEncoder().encodeToString(type1Msg));
            } else {
                // Send Type 3 message
                byte[] type3Msg = createType3Message(challenge);
                headers.set("Authorization", "NTLM " + Base64.getEncoder().encodeToString(type3Msg));
            }

            // Prepare request body
            String requestBody = body != null ? new org.json.JSONObject(body).toString() : null;

            // Make request
            HttpEntity<String> requestEntity = new HttpEntity<>(requestBody, headers);
            ResponseEntity<String> response = restTemplate.exchange(
                baseUrl + "/api/secure",
                method.equals("GET") ? HttpMethod.GET : HttpMethod.POST,
                requestEntity,
                String.class
            );

            // Check for Type 2 message in response
            String authHeader = response.getHeaders().getFirst("WWW-Authenticate");
            if (authHeader != null && authHeader.startsWith("NTLM")) {
                byte[] type2Msg = Base64.getDecoder().decode(authHeader.substring(5));
                challenge = Arrays.copyOfRange(type2Msg, 24, 32);
                return callSecureEndpoint(method, body);  // Retry with Type 3 message
            }

            return response;
        } catch (Exception e) {
            throw new RuntimeException("Failed to call secure endpoint: " + e.getMessage(), e);
        }
    }

    public static void main(String[] args) {
        NTLMClient client = new NTLMClient(
            "http://localhost:8089",
            "DOMAIN",
            "user",
            "Password123!"
        );

        // Test GET request
        ResponseEntity<String> getResponse = client.callSecureEndpoint("GET", null);
        System.out.println("GET Response Status: " + getResponse.getStatusCode());
        System.out.println("GET Response Body: " + getResponse.getBody());

        // Test POST request
        Map<String, Object> postBody = new HashMap<>();
        postBody.put("message", "Hello from NTLM client!");
        ResponseEntity<String> postResponse = client.callSecureEndpoint("POST", postBody);
        System.out.println("POST Response Status: " + postResponse.getStatusCode());
        System.out.println("POST Response Body: " + postResponse.getBody());
    }
} 