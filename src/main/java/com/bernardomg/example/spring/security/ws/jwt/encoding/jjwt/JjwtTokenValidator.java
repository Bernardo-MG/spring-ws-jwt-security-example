/**
 * The MIT License (MIT)
 * <p>
 * Copyright (c) 2022-2025 the original author or authors.
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

package com.bernardomg.example.spring.security.ws.jwt.encoding.jjwt;

import javax.crypto.SecretKey;

import com.bernardomg.example.spring.security.ws.jwt.encoding.TokenDecoder;
import com.bernardomg.example.spring.security.ws.jwt.encoding.TokenValidator;

import io.jsonwebtoken.JwtException;
import lombok.extern.slf4j.Slf4j;

/**
 * Token validator based on the JJWT library.
 *
 * @author Bernardo Mart&iacute;nez Garrido
 *
 */
@Slf4j
public final class JjwtTokenValidator implements TokenValidator {

    /**
     * Token decoder. Without this the token claims can't be validated.
     */
    private final TokenDecoder tokenDecoder;

    /**
     * Constructs a validator with the received arguments.
     *
     * @param secretKey
     *            secret key used for the token
     */
    public JjwtTokenValidator(final SecretKey secretKey) {
        super();

        tokenDecoder = new JjwtTokenDecoder(secretKey);
    }

    @Override
    public final boolean hasExpired(final String token) {
        Boolean expired;

        try {
            // Check if token is expired
            expired = tokenDecoder.decode(token)
                .isExpired();
        } catch (final JwtException e) {
            // Token parsing failed
            log.debug("Failed parsing token", e);
            expired = true;
        }

        return expired;
    }

}
