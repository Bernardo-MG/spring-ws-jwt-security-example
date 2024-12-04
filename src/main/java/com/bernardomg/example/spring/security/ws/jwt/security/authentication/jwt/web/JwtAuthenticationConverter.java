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

import java.util.Optional;

import javax.crypto.SecretKey;

import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;

import com.bernardomg.example.spring.security.ws.jwt.security.authentication.jwt.token.JjwtTokenDecoder;
import com.bernardomg.example.spring.security.ws.jwt.security.authentication.jwt.token.JjwtTokenValidator;
import com.bernardomg.example.spring.security.ws.jwt.security.authentication.jwt.token.TokenDecoder;
import com.bernardomg.example.spring.security.ws.jwt.security.authentication.jwt.token.TokenValidator;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;

/**
 * {@code AuthenticationConverter} which extracts a JWT authentication object from a request.
 *
 * @author Bernardo Mart&iacute;nez Garrido
 *
 */
@Slf4j
public final class JwtAuthenticationConverter implements AuthenticationConverter {

    /**
     * Token header identifier. This is added before the token to tell which kind of token it is. Used to make sure the
     * authentication header is valid.
     */
    private static final String  TOKEN_HEADER_IDENTIFIER = "Bearer";

    /**
     * Token decoder. Required to acquire the subject.
     */
    private final TokenDecoder   tokenDecoder;

    /**
     * Token validator. Expired tokens are rejected.
     */
    private final TokenValidator tokenValidator;

    /**
     * Constructs an authentication converter with the received arguments.
     *
     * @param key
     *            secret key for encoding JWT tokens
     */
    public JwtAuthenticationConverter(final SecretKey key) {
        super();

        tokenDecoder = new JjwtTokenDecoder(key);
        tokenValidator = new JjwtTokenValidator(tokenDecoder);
    }

    @Override
    public final Authentication convert(final HttpServletRequest request) {
        final Optional<String> token;
        final String           subject;
        final Authentication   authentication;

        log.debug("Authenticating {} request to {}", request.getMethod(), request.getServletPath());

        token = getToken(request);

        if (token.isEmpty()) {
            // Missing header
            log.debug("Missing authorization token");
            authentication = null;
        } else if (!tokenValidator.hasExpired(token.get())) {
            // Token not expired
            // Will load a new authentication from the token

            // Takes subject from the token
            subject = tokenDecoder.decode(token.get())
                .getSubject();
            authentication = UsernamePasswordAuthenticationToken.unauthenticated(subject,
                new WebAuthenticationDetailsSource().buildDetails(request));
        } else {
            log.debug("Expired token {}", token.get());
            authentication = null;
        }

        return authentication;
    }

    /**
     * Takes the token from the authorization header. This is expected to be something like
     * {@code Authorization: Bearer [token]}.
     *
     * @param request
     *            request containing the header with the token
     * @return the token if found, or an empty {@code Optional} otherwise
     */
    private final Optional<String> getToken(final HttpServletRequest request) {
        final String           header;
        final Optional<String> token;

        header = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (header == null) {
            // No token received
            token = Optional.empty();
        } else if (header.trim()
            .startsWith(TOKEN_HEADER_IDENTIFIER + " ")) {
            // Token received
            // Take it by removing the identifier
            // TODO: Should be case insensitive
            token = Optional.of(header.substring(TOKEN_HEADER_IDENTIFIER.length())
                .trim());
        } else if (header.trim()
            .startsWith(TOKEN_HEADER_IDENTIFIER)) {
            // Missing token
            // Bearer field
            log.error("Authorization header {} is missing the token", header);
            throw new BadCredentialsException("Empty JWT authentication token");
        } else {
            // Invalid token received
            log.error("Authorization header {} has an invalid structure, can't return token", header);
            throw new BadCredentialsException("Invalid authentication scheme");
        }

        return token;
    }

}
