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

package com.bernardomg.example.ws.security.jwt.security.login.service;

import java.util.Optional;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.bernardomg.example.ws.security.jwt.security.login.model.ImmutableLoginStatus;
import com.bernardomg.example.ws.security.jwt.security.login.model.LoginStatus;

import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

/**
 * Login service.
 *
 * @author Bernardo Mart&iacute;nez Garrido
 *
 */
@Slf4j
public final class BasicLoginService implements LoginService {

    /**
     * Password encoder, for validating passwords.
     */
    private final PasswordEncoder    passwordEncoder;

    /**
     * User details service, to find and validate users.
     */
    private final UserDetailsService userDetailsService;

    /**
     * Builds a service with the specified arguments.
     *
     * @param userDetService
     *            user details service to acquire users
     * @param passEncoder
     *            password encoder to validate passwords
     */
    public BasicLoginService(@NonNull final UserDetailsService userDetService,
            @NonNull final PasswordEncoder passEncoder) {
        super();

        userDetailsService = userDetService;
        passwordEncoder = passEncoder;
    }

    @Override
    public final LoginStatus login(final String username, final String password) {
        final Boolean valid;

        log.debug("Log in attempt for {}", username);

        valid = isValid(username, password);

        return new ImmutableLoginStatus(username, valid);
    }

    private final Boolean isValid(final String username, final String password) {
        final Boolean         valid;
        Optional<UserDetails> details;

        // Find the user
        try {
            details = Optional.ofNullable(userDetailsService.loadUserByUsername(username));
        } catch (final UsernameNotFoundException e) {
            details = Optional.empty();
        }

        if (details.isEmpty()) {
            // No user found for username
            log.debug("No user for username {}", username);
            valid = false;
        } else if (isValid(details.get())) {
            // User exists
            // Validate password
            valid = passwordEncoder.matches(password, details.get()
                .getPassword());
            if (!valid) {
                log.debug("Received password doesn't match the one stored for username {}", username);
            }
        } else {
            // Invalid user
            log.debug("User {} is in an invalid state invalid", username);
            if (!details.get()
                .isAccountNonExpired()) {
                log.debug("User {} account expired", username);
            }
            if (!details.get()
                .isAccountNonLocked()) {
                log.debug("User {} account is locked", username);
            }
            if (!details.get()
                .isCredentialsNonExpired()) {
                log.debug("User {} credentials expired", username);
            }
            if (!details.get()
                .isEnabled()) {
                log.debug("User {} is disabled", username);
            }
            valid = false;
        }

        return valid;
    }

    /**
     * Checks if the user is valid. This means it has no flag marking it as not usable.
     *
     * @param userDetails
     *            user the check
     * @return {@code true} if the user is valid, {@code false} otherwise
     */
    private final Boolean isValid(final UserDetails userDetails) {
        return userDetails.isAccountNonExpired() && userDetails.isAccountNonLocked()
                && userDetails.isCredentialsNonExpired() && userDetails.isEnabled();
    }

}
