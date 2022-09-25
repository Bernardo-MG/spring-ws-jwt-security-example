/**
 * The MIT License (MIT)
 * <p>
 * Copyright (c) 2017-2020 the original author or authors.
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

package com.bernardomg.example.ws.security.jwt.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetailsService;

import com.bernardomg.example.ws.security.jwt.auth.jwt.filter.TokenFilter;
import com.bernardomg.example.ws.security.jwt.auth.jwt.processor.JwtTokenProcessor;
import com.bernardomg.example.ws.security.jwt.auth.jwt.processor.TokenProcessor;

/**
 * Authentication configuration.
 *
 * @author Bernardo Martínez Garrido
 *
 */
@Configuration
public class JwtConfig {

    public JwtConfig() {
        super();
    }

    @Bean("jwtTokenFilter")
    public TokenFilter getJwtTokenFilter(final UserDetailsService userDetService, final TokenProcessor processor) {
        return new TokenFilter(userDetService, processor);
    }

    @Bean("tokenProcessor")
    public TokenProcessor getTokenProcessor(@Value("${jwt.secret}") final String secret,
            @Value("${jwt.validity}") final Integer validity) {
        return new JwtTokenProcessor(secret, validity);
    }

}
