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

package com.bernardomg.example.spring.security.ws.jwt.security.jwt.token;

import java.util.Date;
import java.util.Objects;

import com.bernardomg.example.spring.security.ws.jwt.security.token.TokenDecoder;
import com.bernardomg.example.spring.security.ws.jwt.security.token.TokenValidator;

import io.jsonwebtoken.ExpiredJwtException;
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
     * Token decoder. Without this the token claims can't be validated.
     */
    private final TokenDecoder<JwtTokenData> tokenDataDecoder;

    /**
     * Constructs a validator with the received arguments.
     *
     * @param decoder
     *            token decoder for reading the token claims
     */
    public JwtTokenValidator(final TokenDecoder<JwtTokenData> decoder) {
        super();

        tokenDataDecoder = Objects.requireNonNull(decoder);
    }

    @Override
    public final Boolean hasExpired(final String token) {
        final Date expiration;
        final Date current;
        Boolean    expired;

        try {
            // Acquire expiration claim
            expiration = tokenDataDecoder.decode(token)
                .getExpiration();

            // Compare expiration to current date
            current = new Date();
            expired = expiration.before(current);

            log.debug("Token expires on {}, and the current date is {}. Expired: {}", expiration, current, expired);
        } catch (final ExpiredJwtException e) {
            // Token parsing failed due to expiration date
            log.debug(e.getLocalizedMessage());
            expired = true;
        }

        return expired;
    }

}
