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

package com.bernardomg.example.ws.security.jwt.auth.jwt.filter;

import java.io.IOException;
import java.util.Objects;
import java.util.Optional;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import com.bernardomg.example.ws.security.jwt.auth.jwt.token.TokenValidator;

import lombok.extern.slf4j.Slf4j;

/**
 * Token filter. The actual token specification to use will depend on the {@link TokenValidator} used.
 *
 * @author Bernardo Mart&iacute;nez Garrido
 *
 */
@Slf4j
public final class TokenFilter extends OncePerRequestFilter {

    private final String             tokenHeaderIdentifier = "Bearer";

    /**
     * Token processor. Parses and validates tokens.
     */
    private final TokenValidator     tokenValidator;

    /**
     * User details service. Gives access to the user, to validate the token against it.
     */
    private final UserDetailsService userDetailsService;

    /**
     * Constructs a filter with the received arguments.
     *
     * @param userDetService
     *            user details service
     * @param processor
     *            token processor
     */
    public TokenFilter(final UserDetailsService userDetService, final TokenValidator processor) {
        super();

        userDetailsService = Objects.requireNonNull(userDetService);
        tokenValidator = Objects.requireNonNull(processor);

        // TODO: Test this class
    }

    /**
     * Returns an authentication object created from the user and request.
     *
     * @param userDetails
     *            user for the authentication
     * @param request
     *            request details for the authentication
     * @return an authentication object
     */
    private final Authentication getAuthentication(final UserDetails userDetails, final HttpServletRequest request) {
        final AbstractAuthenticationToken authenticationToken;

        authenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
        authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

        return authenticationToken;
    }

    /**
     * Returns the subject from a token.
     *
     * @param token
     *            the token to parse
     * @return the subject from the token if found, or an empty {@code Optional} otherwise
     */
    private final Optional<String> getSubject(final Optional<String> token) {
        Optional<String> subject;

        if (token.isPresent()) {
            log.debug("Parsing subject from token");
            subject = Optional.ofNullable(tokenValidator.getSubject(token.get()));
        } else {
            // No token received
            subject = Optional.empty();
        }

        return subject;
    }

    /**
     * Takes the token from the authorization header.
     *
     * @param header
     *            header with the token
     * @return the token if found, or an empty {@code Optional} otherwise
     */
    private final Optional<String> getToken(final String header) {
        final Optional<String> token;

        if (header.trim()
            .startsWith(tokenHeaderIdentifier + " ")) {
            // Token received
            // Take it by removing the identifier
            token = Optional.of(header.substring(tokenHeaderIdentifier.length())
                .trim());
        } else {
            // No token received
            token = Optional.empty();
            log.warn("Authorization header '{}' has an invalid structure, can't return token", header);
        }

        return token;
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

    @Override
    protected final void doFilterInternal(final HttpServletRequest request, final HttpServletResponse response,
            final FilterChain chain) throws ServletException, IOException {
        final String           authHeader;
        final Optional<String> token;
        final Optional<String> subject;
        final UserDetails      userDetails;
        final Authentication   authentication;

        authHeader = request.getHeader("Authorization");

        if (authHeader == null) {
            // Missing header
            log.debug("Missing authorization header");
        } else if (SecurityContextHolder.getContext()
            .getAuthentication() == null) {
            // No authentication in context
            // Will load a new authentication from the token

            token = getToken(authHeader);
            subject = getSubject(token);

            // Once we get the token validate it.
            if (subject.isPresent()) {
                log.debug("Validating authentication token for {}", subject.get());
                userDetails = userDetailsService.loadUserByUsername(subject.get());

                if ((isValid(userDetails)) && (!tokenValidator.hasExpired(token.get()))) {
                    // User valid and token not expired

                    log.debug("Valid authentication token. Will load authentication details");

                    // Create and register authentication
                    authentication = getAuthentication(userDetails, request);
                    SecurityContextHolder.getContext()
                        .setAuthentication(authentication);
                }
            }
        }

        chain.doFilter(request, response);
    }

}
