package com.auth.noauth;

import com.auth.base.BaseAuth;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
public class NoAuthApplication {
    public static void main(String[] args) {
        SpringApplication.run(NoAuthApplication.class, args);
    }

    @Configuration
    @EnableWebSecurity
    public static class SecurityConfig extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/api/public/**").permitAll()
                .anyRequest().authenticated()
                .and()
                .addFilter(new NoAuth());
        }
    }

    public static class NoAuth extends BaseAuth {
        public NoAuth() {
            setPort(8080);
        }

        @Override
        protected boolean authenticate(HttpServletRequest request) {
            // No authentication required
            return true;
        }
    }

    @RestController
    @RequestMapping("/api")
    public static class PublicController {
        @GetMapping("/public")
        public Map<String, String> publicEndpoint() {
            Map<String, String> response = new HashMap<>();
            response.put("message", "This is a public endpoint that requires no authentication");
            response.put("status", "success");
            return response;
        }
    }
} 