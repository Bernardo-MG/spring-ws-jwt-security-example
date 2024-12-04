/**
 * The MIT License (MIT)
 * <p>
 * Copyright (c) 2022-2023 the original author or authors.
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

package com.bernardomg.example.spring.security.ws.jwt.security.authentication;

import java.util.Objects;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * Authentication manager which delegates into a {@link UserDetailsService}.
 *
 * @author Bernardo Mart&iacute;nez Garrido
 *
 */
public final class UserDetailsAuthenticationManager implements AuthenticationManager {

    /**
     * User details service to acquire the user.
     */
    final UserDetailsService userDetailsService;

    public UserDetailsAuthenticationManager(final UserDetailsService userDetailsServ) {
        super();

        userDetailsService = Objects.requireNonNull(userDetailsServ);
    }

    @Override
    public final Authentication authenticate(final Authentication authentication) throws AuthenticationException {
        final UserDetails userDetails;

        try {
            userDetails = userDetailsService.loadUserByUsername(authentication.getName());
        } catch (final UsernameNotFoundException e) {
            throw new BadCredentialsException(String.format("User %s not found", authentication.getName()));
        }

        if (!userDetails.isEnabled()) {
            throw new DisabledException(String.format("User %s is disabled", authentication.getName()));
        }
        if (!userDetails.isAccountNonLocked()) {
            throw new LockedException(String.format("User %s is locked", authentication.getName()));
        }
        if (!userDetails.isCredentialsNonExpired()) {
            throw new BadCredentialsException(
                String.format("User %s credentials are expired", authentication.getName()));
        }

        return UsernamePasswordAuthenticationToken.authenticated(userDetails, authentication.getCredentials(),
            userDetails.getAuthorities());
    }

}
