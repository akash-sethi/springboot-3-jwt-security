package com.akash.jwtauth.service;

import com.akash.jwtauth.dto.AuthRequest;
import com.akash.jwtauth.dto.AuthenticationResponse;
import com.akash.jwtauth.dto.RegisterRequest;
import com.akash.jwtauth.entity.Role;
import com.akash.jwtauth.entity.User;
import com.akash.jwtauth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.val;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest request) {
        val user = User
                .builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();

        val savedUser = userRepository.save(user);

        val jwtToken = jwtService.generateToken(savedUser);
        return new AuthenticationResponse(jwtToken);
    }

    public AuthenticationResponse authenticate(AuthRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUserName(), request.getPassword())
        );

        val user = userRepository.findByEmail(
                request.getUserName()).orElseThrow(() -> new UsernameNotFoundException("User not found")
        );

        val jwtToken = jwtService.generateToken(user);

        return new AuthenticationResponse(jwtToken);
    }
}
