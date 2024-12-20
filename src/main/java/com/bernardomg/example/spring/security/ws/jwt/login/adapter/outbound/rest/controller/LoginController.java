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

package com.bernardomg.example.spring.security.ws.jwt.login.adapter.outbound.rest.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.bernardomg.example.spring.security.ws.jwt.login.adapter.outbound.rest.model.LoginRequest;
import com.bernardomg.example.spring.security.ws.jwt.login.domain.model.Credentials;
import com.bernardomg.example.spring.security.ws.jwt.login.domain.model.TokenLoginStatus;
import com.bernardomg.example.spring.security.ws.jwt.login.usecase.service.LoginService;

import lombok.AllArgsConstructor;

/**
 * Login controller. Allows a user to log into the application.
 *
 * @author Bernardo Mart&iacute;nez Garrido
 *
 */
@RestController
@RequestMapping("/login")
@AllArgsConstructor
public class LoginController {

    /**
     * Login service.
     */
    private final LoginService service;

    /**
     * Logs in a user.
     *
     * @param login
     *            login request
     * @return the login status after the login attempt
     */
    @PostMapping
    public TokenLoginStatus login(@RequestBody final LoginRequest login) {
        final Credentials credentials;

        credentials = new Credentials(login.username(), login.password());
        return service.login(credentials);
    }

}
