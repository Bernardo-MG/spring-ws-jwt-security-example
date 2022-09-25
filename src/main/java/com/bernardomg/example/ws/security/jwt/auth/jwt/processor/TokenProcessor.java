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

/**
 * Token processor.
 *
 * @author Bernardo Mart&iacute;nez Garrido
 *
 */
public interface TokenProcessor {

    /**
     * Generates a token for the subject.
     *
     * @param subject
     *            subject of the token
     * @return token for the subject
     */
    public String generateToken(final String subject);

    /**
     * Returns the subject from the received token.
     *
     * @param token
     *            to parse and extract the subject
     * @return subject from the token
     */
    public String getSubject(final String token);

    /**
     * Validates the token and subject.
     *
     * @param token
     *            token to validate
     * @param username
     *            subject of the token
     * @return {@code true} if the token is valid, {@code false} otherwise
     */
    public Boolean validate(final String token, final String username);

}
