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

package com.bernardomg.example.spring.security.ws.jwt.config;

import java.util.function.Predicate;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.bernardomg.example.spring.security.ws.jwt.encoding.TokenEncoder;
import com.bernardomg.example.spring.security.ws.jwt.login.domain.model.Credentials;
import com.bernardomg.example.spring.security.ws.jwt.login.springframework.usecase.service.SpringValidLoginPredicate;
import com.bernardomg.example.spring.security.ws.jwt.login.usecase.encoder.JwtLoginTokenEncoder;
import com.bernardomg.example.spring.security.ws.jwt.login.usecase.encoder.LoginTokenEncoder;
import com.bernardomg.example.spring.security.ws.jwt.login.usecase.service.LoginService;
import com.bernardomg.example.spring.security.ws.jwt.login.usecase.service.TokenLoginService;
import com.bernardomg.example.spring.security.ws.jwt.security.property.JwtProperties;

/**
 * JWT components configuration.
 *
 * @author Bernardo Mart&iacute;nez Garrido
 *
 */
@Configuration
public class LoginConfig {

    /**
     * Default constructor.
     */
    public LoginConfig() {
        super();
    }

    @Bean("loginService")
    public LoginService getLoginService(final UserDetailsService userDetailsService,
            final PasswordEncoder passwordEncoder, final TokenEncoder tokenEncoder, final JwtProperties jwtProperties) {
        final Predicate<Credentials> valid;
        final LoginTokenEncoder      loginTokenEncoder;

        valid = new SpringValidLoginPredicate(userDetailsService, passwordEncoder);

        loginTokenEncoder = new JwtLoginTokenEncoder(tokenEncoder, jwtProperties.getValidity());

        return new TokenLoginService(valid, loginTokenEncoder);
    }

}
