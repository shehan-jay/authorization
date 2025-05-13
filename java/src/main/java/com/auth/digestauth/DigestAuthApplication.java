package com.auth.digestauth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.authentication.www.DigestAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.DigestAuthenticationFilter;

@SpringBootApplication
public class DigestAuthApplication {
    public static void main(String[] args) {
        SpringApplication.run(DigestAuthApplication.class, args);
    }

    @Configuration
    @EnableWebSecurity
    public static class SecurityConfig extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/api/secure/**").authenticated()
                .anyRequest().permitAll()
                .and()
                .addFilter(digestAuthenticationFilter())
                .exceptionHandling()
                .authenticationEntryPoint(digestAuthenticationEntryPoint());
        }

        @Bean
        public DigestAuthenticationEntryPoint digestAuthenticationEntryPoint() {
            DigestAuthenticationEntryPoint entryPoint = new DigestAuthenticationEntryPoint();
            entryPoint.setRealmName("Secure Area");
            entryPoint.setKey("acegi");
            return entryPoint;
        }

        @Bean
        public DigestAuthenticationFilter digestAuthenticationFilter() throws Exception {
            DigestAuthenticationFilter filter = new DigestAuthenticationFilter();
            filter.setUserDetailsService(userDetailsService());
            filter.setAuthenticationEntryPoint(digestAuthenticationEntryPoint());
            return filter;
        }

        @Bean
        public UserDetailsService userDetailsService() {
            UserDetails admin = User.builder()
                .username("admin")
                .password("password123")
                .roles("ADMIN")
                .build();

            UserDetails user = User.builder()
                .username("user")
                .password("userpass")
                .roles("USER")
                .build();

            return new InMemoryUserDetailsManager(admin, user);
        }

        @Bean
        public PasswordEncoder passwordEncoder() {
            return NoOpPasswordEncoder.getInstance(); // For demonstration only
        }
    }
} 