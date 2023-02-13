package com.tenpo.security.auth;

import com.tenpo.security.config.JwtService;
import com.tenpo.security.user.User;
import com.tenpo.security.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

  private final UserRepository repository;

  private final PasswordEncoder passwordEncoder;

  private final JwtService jwtService;

  private final AuthenticationManager authenticationManager;

  public AuthenticationResponse register(RegisterRequest request) {
    final User user = User.builder()
        .firstname(request.getFirstname())
        .lastname(request.getLastname())
        .email(request.getEmail())
        .password(passwordEncoder.encode(request.getPassword()))
        .role(request.getRole())
        .build();
    repository.save(user);
    final String jwtToken = jwtService.generateAccessToken(user);
    return AuthenticationResponse.builder()
        .token(jwtToken)
        .build();
  }

  public AuthenticationResponse authenticate(AuthenticateRequest request) {
    authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(
            request.getEmail(),
            request.getPassword()
        )
    );
    final String email = request.getEmail();
    final User user = repository.findByEmail(email)
        .orElseThrow(() -> new UsernameNotFoundException(String.format("User not found %s", email)));
    final String jwtToken = jwtService.generateAccessToken(user);
    return AuthenticationResponse.builder()
        .token(jwtToken)
        .build();
  }
}
