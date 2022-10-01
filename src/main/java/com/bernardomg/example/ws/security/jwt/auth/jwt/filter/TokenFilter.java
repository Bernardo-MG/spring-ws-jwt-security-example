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
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import com.bernardomg.example.ws.security.jwt.auth.jwt.processor.TokenProcessor;

import lombok.extern.slf4j.Slf4j;

/**
 * Token filter. The actual token specification to use will depend on the {@link TokenProcessor} used.
 *
 * @author Bernardo Mart&iacute;nez Garrido
 *
 */
@Slf4j
public class TokenFilter extends OncePerRequestFilter {

    private final String             tokenHeaderIdentifier = "Bearer";

    /**
     * Token processor. Parses and validates tokens.
     */
    private final TokenProcessor     tokenProcessor;

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
    public TokenFilter(final UserDetailsService userDetService, final TokenProcessor processor) {
        super();

        userDetailsService = Objects.requireNonNull(userDetService);
        tokenProcessor = Objects.requireNonNull(processor);

        // TODO: Test this class
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
            subject = Optional.ofNullable(tokenProcessor.getSubject(token.get()));
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
            token = Optional.of(header.substring(tokenHeaderIdentifier.length() + 1));
        } else {
            // No token received
            token = Optional.empty();
            log.warn("Authorization header '{}' has an invalid structure, can't return token", header);
        }

        return token;
    }

    @Override
    protected void doFilterInternal(final HttpServletRequest request, final HttpServletResponse response,
            final FilterChain chain) throws ServletException, IOException {
        final String                      authHeader;
        final Optional<String>            token;
        final Optional<String>            subject;
        final UserDetails                 userDetails;
        final AbstractAuthenticationToken authenticationToken;

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
                userDetails = userDetailsService.loadUserByUsername(subject.get());

                // if token is valid configure Spring Security to manually set
                // authentication
                if (tokenProcessor.validate(token.get(), userDetails.getUsername())) {
                    // Valid token

                    log.debug("Valid authentication token. Will load authentication details");

                    authenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null,
                        userDetails.getAuthorities());
                    authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    // After setting the Authentication in the context, we specify
                    // that the current user is authenticated. So it passes the
                    // Spring Security Configurations successfully.
                    SecurityContextHolder.getContext()
                        .setAuthentication(authenticationToken);
                }
            }
        }

        chain.doFilter(request, response);
    }

}
