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

package com.bernardomg.example.spring.security.ws.jwt.login.usecase.service;

import java.util.Objects;
import java.util.function.Predicate;

import com.bernardomg.example.spring.security.ws.jwt.login.domain.model.Credentials;
import com.bernardomg.example.spring.security.ws.jwt.login.domain.model.TokenLoginStatus;
import com.bernardomg.example.spring.security.ws.jwt.login.usecase.encoder.LoginTokenEncoder;

import lombok.extern.slf4j.Slf4j;

/**
 * Default implementation of the login service.
 *
 * @author Bernardo Mart&iacute;nez Garrido
 *
 */
@Slf4j
public final class TokenLoginService implements LoginService {

    private final Predicate<Credentials> isValid;

    private final LoginTokenEncoder      loginTokenEncoder;

    public TokenLoginService(final Predicate<Credentials> valid, final LoginTokenEncoder loginTokenEnc) {
        super();

        isValid = Objects.requireNonNull(valid);
        loginTokenEncoder = Objects.requireNonNull(loginTokenEnc);
    }

    @Override
    public final TokenLoginStatus login(final Credentials credentials) {
        final Boolean          valid;
        final TokenLoginStatus status;

        log.debug("Log in attempt for {}", credentials.username());

        valid = isValid.test(credentials);

        status = buildStatus(credentials.username(), valid);

        log.debug("Log in result for {}: {}", credentials.username(), credentials.password());

        return status;
    }

    private final TokenLoginStatus buildStatus(final String username, final boolean logged) {
        final TokenLoginStatus status;
        final String           token;

        if (logged) {
            token = loginTokenEncoder.encode(username);
            status = new TokenLoginStatus(logged, token);
        } else {
            status = new TokenLoginStatus(logged, "");
        }

        return status;
    }

}
