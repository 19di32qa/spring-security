package com.test1.Auth;

import com.test1.Config.JwtService;
import com.test1.Token.Token;
import com.test1.Token.TokenRepo;
import com.test1.Token.TokenType;
import com.test1.User.Role;
import com.test1.User.User;
import com.test1.User.UserRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepo userRepo;
    private final TokenRepo tokenRepo;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthResponse register (RegisterRequest request) {
        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER).build();
        var savedUser = userRepo.save(user);
        var jwtToken = jwtService.generateToken(user);
        savedUserToken(savedUser,jwtToken);
        return AuthResponse.builder().token(jwtToken).build();
    }

    private void savedUserToken(User user, String jwtToken) {
        var token = Token.builder().token(jwtToken).tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .build();
        tokenRepo.save(token);
    }
    private void revokeAllUserToken(User user) {
        var validToken = tokenRepo.findAllValidTokenByUser(user.getId());
        if (validToken == null) {
            return;
        }
        validToken.forEach(token -> {token.setExpired(true);token.setRevoked(true);});
        tokenRepo.saveAll(validToken);
    }

    public AuthResponse auth(AuthRequest request) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(),request.getPassword()));
        var user = userRepo.findByEmail(request.getEmail()).orElseThrow();

        var jwtToken = jwtService.generateToken(user);
        revokeAllUserToken(user);
        savedUserToken(user,jwtToken);
        return AuthResponse.builder().token(jwtToken).build();

    }
}
