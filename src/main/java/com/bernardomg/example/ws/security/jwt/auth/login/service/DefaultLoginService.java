/**
 * The MIT License (MIT)
 * <p>
 * Copyright (c) 2022 the original author or authors.
 * <p>
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * <p>
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * <p>
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package com.bernardomg.example.ws.security.jwt.auth.login.service;

import java.util.Optional;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.bernardomg.example.ws.security.jwt.auth.jwt.processor.TokenGenerator;
import com.bernardomg.example.ws.security.jwt.auth.login.model.ImmutableLoginStatus;
import com.bernardomg.example.ws.security.jwt.auth.login.model.LoginStatus;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Default implementation of the login service.
 *
 * @author Bernardo Mart&iacute;nez Garrido
 *
 */
@Service
@AllArgsConstructor
@Slf4j
public final class DefaultLoginService implements LoginService {

    /**
     * Password encoder, for validating passwords.
     */
    private final PasswordEncoder    passwordEncoder;

    /**
     * Token generator, creates authentication tokens.
     */
    private final TokenGenerator     tokenGenerator;

    /**
     * User details service, to find and validate users.
     */
    private final UserDetailsService userDetailsService;

    @Override
    public final LoginStatus login(final String username, final String password) {
        final LoginStatus     status;
        final String          token;
        final Boolean         logged;
        Optional<UserDetails> details;

        log.debug("Log in attempt for {}", username);

        try {
            details = Optional.of(userDetailsService.loadUserByUsername(username));
        } catch (final UsernameNotFoundException e) {
            details = Optional.empty();
        }

        if (details.isEmpty()) {
            // No user found for username
            log.debug("No user for username {}", username);
            logged = false;
        } else {
            // Validate password
            logged = passwordEncoder.matches(password, details.get()
                .getPassword());
            if (!logged) {
                log.debug("Received password doesn't match the one stored for username {}", username);
            }
        }

        if (logged) {
            // Valid user
            // Generate token
            token = tokenGenerator.generateToken(username);
        } else {
            token = "";
        }

        status = new ImmutableLoginStatus(username, logged, token);

        log.debug("Finished log in attempt for {}. Logged in: {}", username, status.getLogged());

        return status;
    }

}
