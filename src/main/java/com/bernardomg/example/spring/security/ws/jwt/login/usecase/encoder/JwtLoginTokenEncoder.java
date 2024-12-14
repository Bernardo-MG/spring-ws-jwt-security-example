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

package com.bernardomg.example.spring.security.ws.jwt.login.usecase.encoder;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Objects;

import com.bernardomg.example.spring.security.ws.jwt.encoding.JwtTokenData;
import com.bernardomg.example.spring.security.ws.jwt.encoding.TokenEncoder;

import lombok.extern.slf4j.Slf4j;

/**
 * Encodes a JWT token including the permissions for the user.
 *
 * @author Bernardo Mart&iacute;nez Garrido
 *
 */
@Slf4j
public class JwtLoginTokenEncoder implements LoginTokenEncoder {

    /**
     * Token encoder for creating authentication tokens.
     */
    private final TokenEncoder tokenEncoder;

    /**
     * Token validity time in seconds.
     */
    private final Duration     validity;

    public JwtLoginTokenEncoder(final TokenEncoder tknEncoder, final Duration vldt) {
        super();

        tokenEncoder = Objects.requireNonNull(tknEncoder);
        validity = Objects.requireNonNull(vldt);
    }

    @Override
    public final String encode(final String username) {
        final LocalDateTime expiration;
        final LocalDateTime issuedAt;
        final String        token;
        final JwtTokenData  data;

        // Issued right now
        issuedAt = LocalDateTime.now();
        // Expires in a number of seconds equal to validity
        // TODO: handle validity in the encoder
        expiration = LocalDateTime.now()
            .plus(validity);

        // Build token data for the wrapped encoder
        data = JwtTokenData.builder()
            .withSubject(username)
            .withIssuedAt(issuedAt)
            .withNotBefore(issuedAt)
            .withExpiration(expiration)
            .build();

        token = tokenEncoder.encode(data);

        log.debug("Created token for subject {} with expiration date {}", username, expiration);

        return token;
    }

}
