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

package com.bernardomg.example.spring.security.ws.jwt.security.jwt.web.authentication;

import java.io.IOException;

import javax.crypto.SecretKey;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
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
 *
 * @author Bernardo Mart&iacute;nez Garrido
 *
 */
@Slf4j
public final class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final AuthenticationConverter authenticationConverter;

    /**
     * Constructs a filter with the received arguments.
     *
     * @param userDetService
     *            user details service
     * @param key
     *            secret key for encoding JWT tokens
     */
    public JwtAuthenticationFilter(final UserDetailsService userDetService, final SecretKey key) {
        super();

        authenticationConverter = new JwtAuthenticationConverter(userDetService, key);
    }

    @Override
    protected final void doFilterInternal(final HttpServletRequest request, final HttpServletResponse response,
            final FilterChain chain) throws ServletException, IOException {
        final Authentication authentication;

        log.debug("Authenticating {} request to {}", request.getMethod(), request.getServletPath());

        authentication = authenticationConverter.convert(request);
        if (authentication != null) {
            SecurityContextHolder.getContext()
                .setAuthentication(authentication);

            // User valid
            log.debug("Authenticated {} request for {} to {}", request.getMethod(), authentication.getName(),
                request.getServletPath());
        }

        chain.doFilter(request, response);
    }

}
