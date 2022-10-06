
package com.bernardomg.example.ws.security.jwt.test.auth.login.service.integration;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.jdbc.Sql;

import com.bernardomg.example.ws.security.jwt.auth.login.model.LoginDetails;
import com.bernardomg.example.ws.security.jwt.auth.login.service.LoginService;
import com.bernardomg.example.ws.security.jwt.test.config.annotation.IntegrationTest;

@IntegrationTest
@DisplayName("Login service - no privileges")
@Sql({ "/db/queries/user/single.sql", "/db/queries/role/single.sql", "/db/queries/relationship/user_role.sql" })
public class ITLoginServiceNoPrivileges {

    @Autowired
    private LoginService service;

    public ITLoginServiceNoPrivileges() {
        super();
    }

    @Test
    @DisplayName("An existing user can't log in")
    public final void testLogin_valid() {
        final LoginDetails result;

        result = service.login("admin", "1234");

        Assertions.assertFalse(result.getLogged());
    }

}
