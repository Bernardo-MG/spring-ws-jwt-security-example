
package com.bernardomg.example.ws.security.jwt.test.auth.login.service.integration;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.jdbc.Sql;

import com.bernardomg.example.ws.security.jwt.auth.login.model.LoginStatus;
import com.bernardomg.example.ws.security.jwt.auth.login.service.LoginService;
import com.bernardomg.example.ws.security.jwt.test.config.annotation.IntegrationTest;

@IntegrationTest
@DisplayName("Login service")
@Sql({ "/db/queries/user/single.sql", "/db/queries/role/single.sql", "/db/queries/privilege/multiple.sql",
        "/db/queries/relationship/role_privilege.sql", "/db/queries/relationship/user_role.sql" })
public class ITLoginService {

    @Autowired
    private LoginService service;

    public ITLoginService() {
        super();
    }

    @Test
    @DisplayName("An existing user with invalid password doesn't log in")
    public final void testLogin_invalidPassword() throws Exception {
        final LoginStatus result;

        result = service.login("admin", "abc");

        Assertions.assertFalse(result.getLogged());
    }

    @Test
    @DisplayName("A not existing user doesn't log in")
    public final void testLogin_notExisting() throws Exception {
        final LoginStatus result;

        result = service.login("abc", "1234");

        Assertions.assertFalse(result.getLogged());
    }

    @Test
    @DisplayName("An existing user with valid password logs in")
    public final void testLogin_valid() throws Exception {
        final LoginStatus result;

        result = service.login("admin", "1234");

        Assertions.assertTrue(result.getLogged());
    }

}
