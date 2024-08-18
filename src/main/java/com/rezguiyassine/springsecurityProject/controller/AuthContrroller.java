package com.rezguiyassine.springsecurityProject.controller;


import com.rezguiyassine.springsecurityProject.config.JwtService;
import com.rezguiyassine.springsecurityProject.user.UserReposotiry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthContrroller {
    private final AuthenticationService authenticationService;

    private final UserReposotiry userReposotiry;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;



    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> registerRequest(@RequestBody RegisterRequest registerRequest){
    return ResponseEntity.ok(authenticationService.register(registerRequest));


    }

    @PostMapping("/login")

    public ResponseEntity<AuthenticationResponse> loginRequest(@RequestBody LoginRequest loginRequest){
        return ResponseEntity.ok((authenticationService.login(loginRequest)));

    }
}
