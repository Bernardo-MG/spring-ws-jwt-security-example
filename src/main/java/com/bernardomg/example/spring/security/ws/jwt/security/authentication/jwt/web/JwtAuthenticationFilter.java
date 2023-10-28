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

package com.bernardomg.example.spring.security.ws.jwt.security.authentication.jwt.web;

import java.io.IOException;
import java.util.Objects;

import javax.crypto.SecretKey;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

/**
 * JWT token authentication filter. Takes the JWT token from the request, validates it and initialises the user
 * authentication.
 * <h2>Header</h2>
 * <p>
 * The token should come in the Authorization header, which must follow a structure like this:
 * {@code Authorization: Bearer [token]}. This is case insensitive.
 * <p>
 * Acquiring the token is delegated to {@link JwtAuthenticationConverter}.
 *
 * @author Bernardo Mart&iacute;nez Garrido
 *
 */
@Slf4j
public final class JwtAuthenticationFilter extends OncePerRequestFilter {

    /**
     * Authentication converter, which creates the authentication object from the request.
     */
    private final AuthenticationConverter authenticationConverter;

    /**
     * Authentication manager, which acquires the actual authentication object.
     */
    private final AuthenticationManager   authenticationManager;

    /**
     * Constructs a filter with the received arguments.
     *
     * @param authManager
     *            authentication manager
     * @param key
     *            secret key for encoding JWT tokens
     */
    public JwtAuthenticationFilter(final AuthenticationManager authManager, final SecretKey key) {
        super();

        authenticationManager = Objects.requireNonNull(authManager);
        authenticationConverter = new JwtAuthenticationConverter(key);
    }

    @Override
    protected final void doFilterInternal(final HttpServletRequest request, final HttpServletResponse response,
            final FilterChain chain) throws ServletException, IOException {
        final Authentication authRequest;
        final Authentication authentication;

        log.debug("Authenticating {} request to {}", request.getMethod(), request.getServletPath());

        authRequest = authenticationConverter.convert(request);
        if (authRequest == null) {
            // Invalid user
            log.debug("Couldn't authenticate request {} request to {}", request.getMethod(), request.getServletPath());
            SecurityContextHolder.getContext()
                .setAuthentication(null);
        } else {
            authentication = authenticationManager.authenticate(authRequest);

            SecurityContextHolder.getContext()
                .setAuthentication(authentication);

            // Valid user
            log.debug("Authenticated {} request for {} to {}", request.getMethod(), authentication.getName(),
                request.getServletPath());
        }

        chain.doFilter(request, response);
    }

}
