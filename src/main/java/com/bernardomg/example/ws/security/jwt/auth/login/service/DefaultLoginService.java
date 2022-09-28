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

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.bernardomg.example.ws.security.jwt.auth.jwt.processor.TokenProcessor;
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
     * Token processor, to handle authentication tokens.
     */
    private final TokenProcessor     tokenProcessor;

    /**
     * User details service, to find and validate users.
     */
    private final UserDetailsService userDetailsService;

    @Override
    public final LoginStatus login(final String username, final String password) {
        final ImmutableLoginStatus status;
        final String               token;
        final UserDetails          userDetails;
        Boolean                    validUsername;
        Boolean                    validPassword;

        log.trace("Generating token for {}", username);

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

        if ((validUsername) && (validPassword)) {
            // Valid user
            // Generate token
            token = tokenProcessor.generateToken(username);
            status = new ImmutableLoginStatus(username, true, token);
        } else {
            status = new ImmutableLoginStatus(username, false, "");
        }

        return status;
    }

}
