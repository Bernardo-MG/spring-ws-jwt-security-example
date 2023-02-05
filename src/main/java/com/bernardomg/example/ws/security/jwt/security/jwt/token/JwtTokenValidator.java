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

package com.bernardomg.example.ws.security.jwt.security.jwt.token;

import java.util.Date;
import java.util.Objects;
import java.util.function.Function;

import javax.crypto.SecretKey;

import com.bernardomg.example.ws.security.jwt.security.token.validator.TokenValidator;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;

/**
 * JWT token validator.
 *
 * @author Bernardo Mart&iacute;nez Garrido
 *
 */
@Slf4j
public final class JwtTokenValidator implements TokenValidator {

    /**
     * JWT parser for reading tokens.
     */
    private final JwtParser parser;

    /**
     * Constructs a validator with the received arguments.
     *
     * @param key
     *            key used when generating tokens
     */
    public JwtTokenValidator(final SecretKey key) {
        super();

        Objects.requireNonNull(key);

        parser = Jwts.parserBuilder()
            .setSigningKey(key)
            .build();
    }

    @Override
    public final String getSubject(final String token) {
        final String subject;

        subject = getClaim(token, Claims::getSubject);

        log.debug("Found subject {}", subject);

        return subject;
    }

    @Override
    public final Boolean hasExpired(final String token) {
        final Date expiration;
        final Date current;
        Boolean    expired;

        try {
            expiration = getClaim(token, Claims::getExpiration);

            current = new Date();
            expired = expiration.before(current);

            log.debug("Token expires on {}, and the current date is {}. Expired? {}", expiration, current, expired);
        } catch (final ExpiredJwtException e) {
            log.debug(e.getLocalizedMessage());
            expired = true;
        }

        return expired;
    }

    /**
     * Returns all claims from the token.
     *
     * @param token
     *            token to parse
     * @return all the claims from the token
     */
    private final Claims getAllClaims(final String token) {
        return parser.parseClaimsJws(token)
            .getBody();
    }

    /**
     * Returns a claim from the token, defined through the claim resolver.
     *
     * @param <T>
     *            type of the claim
     * @param token
     *            token to parse
     * @param resolver
     *            claim resolver
     * @return the claim from the token and resolver
     */
    private final <T> T getClaim(final String token, final Function<Claims, T> resolver) {
        final Claims claims;

        claims = getAllClaims(token);
        return resolver.apply(claims);
    }

}
