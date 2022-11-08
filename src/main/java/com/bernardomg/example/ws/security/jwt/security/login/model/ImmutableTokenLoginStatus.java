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

package com.bernardomg.example.ws.security.jwt.security.login.model;

import lombok.Data;
import lombok.NonNull;

/**
 * Immutable implementation of {@link TokenLoginStatus}.
 *
 * @author Bernardo Mart&iacute;nez Garrido
 *
 */
@Data
public final class ImmutableTokenLoginStatus implements TokenLoginStatus {

    /**
     * Flag telling if the login was successful.
     */
    private final Boolean logged;

    /**
     * Security token.
     */
    private final String  token;

    /**
     * Username of the user who attempted login.
     */
    private final String  username;

    /**
     * Builds a login status with the specified arguments.
     *
     * @param user
     *            username
     * @param flag
     *            logged status
     * @param tokn
     *            authentication token
     */
    public ImmutableTokenLoginStatus(@NonNull final String user, @NonNull final Boolean flag,
            @NonNull final String tokn) {
        super();

        username = user;
        logged = flag;
        token = tokn;
    }

}
