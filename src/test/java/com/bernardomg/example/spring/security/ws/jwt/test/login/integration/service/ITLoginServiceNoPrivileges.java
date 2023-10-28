
package com.bernardomg.example.spring.security.ws.jwt.test.login.integration.service;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import com.bernardomg.example.spring.security.ws.jwt.security.login.model.LoginStatus;
import com.bernardomg.example.spring.security.ws.jwt.security.login.service.LoginService;
import com.bernardomg.example.spring.security.ws.jwt.test.config.annotation.IntegrationTest;
import com.bernardomg.example.spring.security.ws.jwt.test.security.user.config.ValidUser;

@IntegrationTest
@DisplayName("Login service - no privileges")
@ValidUser
public class ITLoginServiceNoPrivileges {

    @Autowired
    private LoginService service;

    public ITLoginServiceNoPrivileges() {
        super();
    }

    @Test
    @DisplayName("An existing user can't log in")
    public final void testLogin_valid() {
        final LoginStatus result;

        result = service.login("admin", "1234");

        Assertions.assertFalse(result.getLogged());
    }

}
