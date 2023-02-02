
package com.bernardomg.example.ws.security.jwt.test.security.login.service.integration;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.jdbc.Sql;

import com.bernardomg.example.ws.security.jwt.security.login.model.LoginStatus;
import com.bernardomg.example.ws.security.jwt.security.login.service.BasicLoginService;
import com.bernardomg.example.ws.security.jwt.test.config.annotation.IntegrationTest;

@IntegrationTest
@DisplayName("Token login service")
public class ITBasicLoginService {

    @Autowired
    private PasswordEncoder    passEncoder;

    private BasicLoginService  service;

    @Autowired
    private UserDetailsService userDetService;

    public ITBasicLoginService() {
        super();
    }

    @BeforeEach
    public void initializeService() {
        service = new BasicLoginService(userDetService, passEncoder);
    }

    @Test
    @DisplayName("Doesn't log in a disabled user")
    @Sql({ "/db/queries/user/disabled.sql", "/db/queries/security/default_role.sql" })
    public void testLogIn_Disabled() {
        final LoginStatus status;

        status = service.login("admin", "1234");

        Assertions.assertFalse(status.getLogged());
        Assertions.assertEquals("admin", status.getUsername());
    }

    @Test
    @DisplayName("Logs in with a valid user")
    @Sql({ "/db/queries/user/single.sql", "/db/queries/security/default_role.sql" })
    public void testLogIn_Valid() {
        final LoginStatus details;

        details = service.login("admin", "1234");

        Assertions.assertTrue(details.getLogged());
        Assertions.assertEquals("admin", details.getUsername());
    }

}
