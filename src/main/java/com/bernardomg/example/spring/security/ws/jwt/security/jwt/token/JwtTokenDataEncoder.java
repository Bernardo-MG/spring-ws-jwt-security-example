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

import java.util.Objects;

import javax.crypto.SecretKey;

import com.bernardomg.example.spring.security.ws.jwt.security.token.provider.TokenEncoder;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;

/**
 * JWT data token encoder.
 *
 * @author Bernardo Mart&iacute;nez Garrido
 *
 */
@Slf4j
public final class JwtTokenDataEncoder implements TokenEncoder<JwtTokenData> {

    /**
     * Secret key for generating tokens. Created from the secret received when constructing the provider.
     */
    private final SecretKey key;

    /**
     * Constructs an encoder with the received arguments.
     *
     * @param secretKey
     *            key used when generating tokens
     */
    public JwtTokenDataEncoder(final SecretKey secretKey) {
        super();

        key = Objects.requireNonNull(secretKey);
    }

    @Override
    public final String generateToken(final JwtTokenData data) {
        final String token;

        token = Jwts.builder()
            .setSubject(data.getSubject())
            .setIssuedAt(data.getIssuedAt())
            .setExpiration(data.getExpiration())
            .signWith(key, SignatureAlgorithm.HS512)
            .compact();

        log.debug("Created token from {}", data);

        return token;
    }

}
