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

package com.bernardomg.example.ws.security.jwt.auth.jwt.token;

import java.util.Date;
import java.util.Objects;

import javax.crypto.SecretKey;

import com.bernardomg.example.ws.security.jwt.auth.token.TokenProvider;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;

/**
 * JWT token provider.
 *
 * @author Bernardo Mart&iacute;nez Garrido
 *
 */
@Slf4j
public final class JwtTokenProvider implements TokenProvider {

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
     * @param secretKey
     *            key used when generating tokens
     * @param validityTime
     *            token validity time in seconds
     */
    public JwtTokenProvider(final SecretKey secretKey, final Integer validityTime) {
        super();

        key = Objects.requireNonNull(secretKey);
        validity = Objects.requireNonNull(validityTime);
    }

    @Override
    public final String generateToken(final String subject) {
        final Date   expiration;
        final Date   issuedAt;
        final String token;

        // Issued right now
        issuedAt = new Date();
        // Expires in a number of seconds equal to validity
        expiration = new Date(System.currentTimeMillis() + (validity * 1000L));

        token = Jwts.builder()
            .setSubject(subject)
            .setIssuedAt(issuedAt)
            .setExpiration(expiration)
            .signWith(key, SignatureAlgorithm.HS512)
            .compact();

        log.debug("Created token for subject {} with expiration date {}", subject, expiration);

        return token;
    }

}
