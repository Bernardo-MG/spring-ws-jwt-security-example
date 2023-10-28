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

package com.bernardomg.example.spring.security.ws.jwt.test.domain.entity.controller.integration;

import java.time.Duration;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.RequestBuilder;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import com.bernardomg.example.spring.security.ws.jwt.security.login.service.JwtLoginTokenEncoder;
import com.bernardomg.example.spring.security.ws.jwt.security.login.service.LoginTokenEncoder;
import com.bernardomg.example.spring.security.ws.jwt.test.config.annotation.MvcIntegrationTest;
import com.bernardomg.example.spring.security.ws.jwt.test.security.authentication.jwt.token.config.TokenConstants;
import com.bernardomg.example.spring.security.ws.jwt.test.security.user.config.ExpiredUser;

@MvcIntegrationTest
@DisplayName("Example entity controller - security - expired user")
@ExpiredUser
public final class ITExampleEntityControllerSecurityExpiredUser {

    @Autowired
    private MockMvc                 mockMvc;

    private final LoginTokenEncoder tokenEncoder = new JwtLoginTokenEncoder(TokenConstants.KEY, Duration.ofHours(1));

    public ITExampleEntityControllerSecurityExpiredUser() {
        super();
    }

    @Test
    @DisplayName("An authenticated request is not authorized")
    public final void testGet_authenticated_notAuthorized() throws Exception {
        final ResultActions result;

        result = mockMvc.perform(getRequestAuthorized());

        // The operation was accepted
        result.andExpect(MockMvcResultMatchers.status()
            .isUnauthorized());
    }

    private final RequestBuilder getRequestAuthorized() {
        final String token;

        token = tokenEncoder.encode("admin");

        return MockMvcRequestBuilders.get("/rest/entity")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + token);
    }

}
