
package com.bernardomg.example.ws.security.jwt.auth.login.service;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.bernardomg.example.ws.security.jwt.auth.jwt.processor.TokenProcessor;
import com.bernardomg.example.ws.security.jwt.auth.login.model.DtoLoginStatus;
import com.bernardomg.example.ws.security.jwt.auth.login.model.LoginStatus;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@AllArgsConstructor
@Slf4j
public final class DefaultLoginService implements LoginService {

    private final PasswordEncoder    passwordEncoder;

    private final TokenProcessor     tokenProcessor;

    private final UserDetailsService userDetailsService;

    @Override
    public final LoginStatus login(final String username, final String password) {
        final DtoLoginStatus status;
        final String         token;
        final UserDetails    userDetails;
        Boolean              validUsername;
        Boolean              validPassword;

        log.trace("Generating token for {}", username);

        // TODO: Get user and check password
        try {
            userDetails = userDetailsService.loadUserByUsername(username);
            validUsername = userDetails.getUsername()
                .equals(username);
            validPassword = passwordEncoder.matches(password, userDetails.getPassword());
        } catch (final UsernameNotFoundException e) {
            log.debug("Username {} not found", username);
            validUsername = false;
            validPassword = false;
        }

        status = new DtoLoginStatus();
        if ((validUsername) && (validPassword)) {
            // Valid user
            // Generate token
            token = tokenProcessor.generateToken(username);
            status.setToken(token);
            status.setLogged(true);
        } else {
            status.setToken("");
            status.setLogged(false);
        }

        return status;
    }

}
