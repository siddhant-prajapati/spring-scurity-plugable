package com.plugable.spring.security.controller;

import com.plugable.spring.security.model.User;
import com.plugable.spring.security.service.JwtTokenProvider;
import com.plugable.spring.security.service.UserDetailsServiceImpl;
import com.plugable.spring.security.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.Objects;

@RestController
@RequestMapping("/api")
public class RegistrationController {

    @Autowired
    private UserService userService;

    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @PostMapping("/auth/register")
    public ResponseEntity<User> registerUser(@RequestBody User user) {
        User newUser = userService.createUser(user);
        return ResponseEntity.ok(newUser);
    }

    @PostMapping("/auth/login")
    public ResponseEntity<String> loginUser(@RequestBody User loginUser) {
        UserDetails userDetails = userDetailsService.loadUserByUsername(loginUser.getUsername());
        if (Objects.nonNull(userDetails)) {
            Authentication authentication = jwtTokenProvider.getAuthentication(userDetails);
            String token = jwtTokenProvider.generateToken(authentication);
            return ResponseEntity.ok(token);
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logoutUser() {
        // Invalidate the session or token here
        return ResponseEntity.ok("User logged out successfully");
    }
}
