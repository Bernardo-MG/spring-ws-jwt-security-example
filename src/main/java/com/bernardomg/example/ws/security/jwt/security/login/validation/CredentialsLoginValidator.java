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

package com.bernardomg.example.ws.security.jwt.security.login.validation;

import java.util.Optional;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

/**
 * Basic login validator, which checks the credentials with these rules:
 * <ul>
 * <li>There is a user for the received username</li>
 * <li>Received password matches with the user password</li>
 * </ul>
 * <h2>Finding the user</h2>
 * <p>
 * {@link UserDetailsService} is used for finding the user. This means that only those users available to the Spring
 * security context will be valid.
 *
 * @author Bernardo Mart&iacute;nez Garrido
 *
 */
@Slf4j
public final class CredentialsLoginValidator implements LoginValidator {

    /**
     * Password encoder, for validating passwords.
     */
    private final PasswordEncoder    passwordEncoder;

    /**
     * User details service, to find and validate users.
     */
    private final UserDetailsService userDetailsService;

    public CredentialsLoginValidator(@NonNull final UserDetailsService userDetsService,
            @NonNull final PasswordEncoder passEncoder) {
        super();

        userDetailsService = userDetsService;
        passwordEncoder = passEncoder;
    }

    @Override
    public final Boolean isValid(final String username, final String password) {
        final Boolean         valid;
        Optional<UserDetails> details;

        // Find the user
        try {
            details = Optional.of(userDetailsService.loadUserByUsername(username));
        } catch (final UsernameNotFoundException e) {
            details = Optional.empty();
        }

        if (details.isEmpty()) {
            // No user found for username
            log.debug("No user for username {}", username);
            valid = false;
        } else {
            // User exists
            // Validate password
            valid = passwordEncoder.matches(password, details.get()
                .getPassword());
            if (!valid) {
                log.debug("Received password doesn't match the one stored for username {}", username);
            }
        }

        return valid;
    }

}
