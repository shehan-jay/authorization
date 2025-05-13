package com.auth.digestauth;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/secure")
public class SecureController {

    @GetMapping
    public Map<String, String> secureEndpoint(Authentication authentication) {
        Map<String, String> response = new HashMap<>();
        response.put("message", "This is a secure endpoint that requires digest authentication");
        response.put("status", "success");
        response.put("user", authentication.getName());
        return response;
    }
} 