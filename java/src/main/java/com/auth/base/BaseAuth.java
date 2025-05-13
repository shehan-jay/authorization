package com.auth.base;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.filter.OncePerRequestFilter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Base class for authentication handlers.
 */
public abstract class BaseAuth extends OncePerRequestFilter {
    /** Default port number. */
    protected int port = 8080;

    /**
     * Filter implementation for authentication.
     * @param request HTTP request
     * @param response HTTP response
     * @param filterChain Filter chain
     * @throws ServletException if servlet error occurs
     * @throws IOException if I/O error occurs
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            if (authenticate(request)) {
                filterChain.doFilter(request, response);
            } else {
                Map<String, String> errorResponse = new HashMap<>();
                errorResponse.put("message", "Authentication failed");
                errorResponse.put("status", "error");
                
                response.setStatus(HttpStatus.UNAUTHORIZED.value());
                response.setContentType("application/json");
                response.getWriter().write(convertMapToJson(errorResponse));
            }
        } catch (Exception e) {
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("message", "Authentication error: " + e.getMessage());
            errorResponse.put("status", "error");
            
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.setContentType("application/json");
            response.getWriter().write(convertMapToJson(errorResponse));
        }
    }

    /**
     * Authenticate the request.
     * @param request HTTP request to authenticate
     * @return true if authentication is successful, false otherwise
     */
    protected abstract boolean authenticate(HttpServletRequest request);

    /**
     * Get the port number for the server.
     * @return The port number
     */
    public int getPort() {
        return port;
    }

    /**
     * Set the port number for the server.
     * @param port The port number to set
     */
    public void setPort(int port) {
        this.port = port;
    }

    /**
     * Convert a map to JSON string.
     * @param map Map to convert
     * @return JSON string representation of the map
     */
    protected String convertMapToJson(Map<String, String> map) {
        StringBuilder json = new StringBuilder();
        json.append("{");
        boolean first = true;
        for (Map.Entry<String, String> entry : map.entrySet()) {
            if (!first) {
                json.append(",");
            }
            json.append("\"").append(entry.getKey()).append("\":\"")
                .append(entry.getValue()).append("\"");
            first = false;
        }
        json.append("}");
        return json.toString();
    }
} 