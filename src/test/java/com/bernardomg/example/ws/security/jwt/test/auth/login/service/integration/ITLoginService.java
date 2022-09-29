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

package com.bernardomg.example.ws.security.jwt.test.auth.login.service.integration;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.jdbc.Sql;

import com.bernardomg.example.ws.security.jwt.auth.login.model.LoginStatus;
import com.bernardomg.example.ws.security.jwt.auth.login.service.DefaultLoginService;
import com.bernardomg.example.ws.security.jwt.test.config.annotation.IntegrationTest;

@IntegrationTest
@DisplayName("Default login service")
@Sql({ "/db/queries/user/single.sql", "/db/queries/role/single.sql", "/db/queries/privilege/multiple.sql",
        "/db/queries/relationship/role_privilege.sql", "/db/queries/relationship/user_role.sql" })
public class ITLoginService {

    @Autowired
    private DefaultLoginService service;

    public ITLoginService() {
        super();
    }

    @Test
    @DisplayName("Generates no token for an invalid password")
    public void testLogin_invalidPassword_notGeneratesToken() {
        final LoginStatus status;

        status = service.login("admin", "abc");

        Assertions.assertTrue(status.getToken()
            .isEmpty());
    }

    @Test
    @DisplayName("Doesn't log in with an invalid password")
    public void testLogin_invalidPassword_notLogged() {
        final LoginStatus status;

        status = service.login("admin", "abc");

        Assertions.assertFalse(status.getLogged());
    }

    @Test
    @DisplayName("Generates no token for a not existing user")
    public void testLogin_notExisting_notGeneratesToken() {
        final LoginStatus status;

        status = service.login("abc", "1234");

        Assertions.assertTrue(status.getToken()
            .isEmpty());
    }

    @Test
    @DisplayName("Doesn't log in a not existing user")
    public void testLogin_notExisting_notLogged() {
        final LoginStatus status;

        status = service.login("abc", "1234");

        Assertions.assertFalse(status.getLogged());
    }

    @Test
    @DisplayName("Generates a token for valid user")
    public void testLogin_valid_generatesToken() {
        final LoginStatus status;

        status = service.login("admin", "1234");

        Assertions.assertFalse(status.getToken()
            .isEmpty());
    }

    @Test
    @DisplayName("Logs in a valid user")
    public void testLogin_valid_logged() {
        final LoginStatus status;

        status = service.login("admin", "1234");

        Assertions.assertTrue(status.getLogged());
    }

}
