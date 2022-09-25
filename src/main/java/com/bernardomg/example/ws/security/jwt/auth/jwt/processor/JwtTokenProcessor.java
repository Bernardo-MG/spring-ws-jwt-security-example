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

package com.bernardomg.example.ws.security.jwt.auth.jwt.processor;

import java.nio.charset.Charset;
import java.util.Date;
import java.util.Objects;
import java.util.function.Function;

import javax.crypto.SecretKey;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;

/**
 * JWT token processor.
 * <p>
 * Expects the secret to be encoded on UTF-8.
 *
 * @author Bernardo Mart&iacute;nez Garrido
 *
 */
@Slf4j
public final class JwtTokenProcessor implements TokenProcessor {

    /**
     * Charset used by the secret received when constructing.
     */
    private final Charset   charset = Charset.forName("UTF-8");

    /**
     * Secret key for generating tokens. Created from the secret received when constructing the processor.
     */
    private final SecretKey key;

    /**
     * Token validity time in seconds.
     */
    private final Integer   validity;

    /**
     * Constructs a processor with the received arguments.
     *
     * @param secret
     *            secret used when generating tokens
     * @param validityTime
     *            token validity time in seconds
     */
    public JwtTokenProcessor(final String secret, final Integer validityTime) {
        super();

        key = Keys.hmacShaKeyFor(secret.getBytes(charset));
        validity = Objects.requireNonNull(validityTime);
    }

    @Override
    public final String generateToken(final String subject) {
        final Date expiration;
        final Date issuedAt;

        // Issued right now
        issuedAt = new Date();
        // Expires in a number of seconds equal to validity
        expiration = new Date(System.currentTimeMillis() + (validity * 1000));

        log.debug("Setting expiration date {}", expiration);

        return Jwts.builder()
            .setSubject(subject)
            .setIssuedAt(issuedAt)
            .setExpiration(expiration)
            .signWith(key, SignatureAlgorithm.HS512)
            .compact();
    }

    @Override
    public final String getSubject(final String token) {
        final String subject;

        subject = getClaim(token, Claims::getSubject);

        log.debug("Found subject {}", subject);

        return subject;
    }

    @Override
    public final Boolean validate(final String token, final String subject) {
        final String  subj;
        final Boolean valid;

        if (isExpired(token)) {
            log.debug("Expired token");
            valid = false;
        } else {
            subj = getSubject(token);

            if (!subj.equals(subject)) {
                log.debug("Received subject {} does not match subject {} from token", subject, subj);
                valid = false;
            } else {
                log.debug("Valid token");
                valid = true;
            }
        }

        return valid;
    }

    /**
     * Returns all claims from the token.
     *
     * @param token
     *            token to parse
     * @return all the claims from the token
     */
    private final Claims getAllClaims(final String token) {
        return Jwts.parserBuilder()
            .setSigningKey(key)
            .build()
            .parseClaimsJws(token)
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

    /**
     * Returns if the token is expired.
     *
     * @param token
     *            token to parse
     * @return {@code true} if the token is expired, {@code false} otherwise
     */
    private final Boolean isExpired(final String token) {
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

}
