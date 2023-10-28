
package com.bernardomg.example.spring.security.ws.jwt.test.login.integration.service;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import com.bernardomg.example.spring.security.ws.jwt.security.login.model.LoginStatus;
import com.bernardomg.example.spring.security.ws.jwt.security.login.service.LoginService;
import com.bernardomg.example.spring.security.ws.jwt.test.config.annotation.IntegrationTest;
import com.bernardomg.example.spring.security.ws.jwt.test.security.user.config.CredentialsExpiredUser;
import com.bernardomg.example.spring.security.ws.jwt.test.security.user.config.DisabledUser;
import com.bernardomg.example.spring.security.ws.jwt.test.security.user.config.ExpiredUser;
import com.bernardomg.example.spring.security.ws.jwt.test.security.user.config.LockedUser;
import com.bernardomg.example.spring.security.ws.jwt.test.security.user.config.UserWithoutPermissions;
import com.bernardomg.example.spring.security.ws.jwt.test.security.user.config.ValidUser;

@IntegrationTest
@DisplayName("Login service")
class ITLoginService {

    @Autowired
    private LoginService service;

    public ITLoginService() {
        super();
    }

    @Test
    @DisplayName("A user with credentials expired doesn't log in")
    @CredentialsExpiredUser
    void testLogin_credentialsExpired() {
        final LoginStatus result;

        result = service.login("admin", "abc");

        Assertions.assertFalse(result.getLogged());
    }

    @Test
    @DisplayName("A disbled user doesn't log in")
    @DisabledUser
    void testLogin_disabled() {
        final LoginStatus result;

        result = service.login("admin", "abc");

        Assertions.assertFalse(result.getLogged());
    }

    @Test
    @DisplayName("A disbled user doesn't log in")
    @ExpiredUser
    void testLogin_expired() {
        final LoginStatus result;

        result = service.login("admin", "abc");

        Assertions.assertFalse(result.getLogged());
    }

    @Test
    @DisplayName("An existing user with invalid password doesn't log in")
    @ValidUser
    void testLogin_invalidPassword() {
        final LoginStatus result;

        result = service.login("admin", "abc");

        Assertions.assertFalse(result.getLogged());
    }

    @Test
    @DisplayName("A disbled user doesn't log in")
    @LockedUser
    void testLogin_locked() {
        final LoginStatus result;

        result = service.login("admin", "abc");

        Assertions.assertFalse(result.getLogged());
    }

    @Test
    @DisplayName("A not existing user doesn't log in")
    void testLogin_noData() {
        final LoginStatus result;

        result = service.login("admin", "abc");

        Assertions.assertFalse(result.getLogged());
    }

    @Test
    @DisplayName("A user without permissions can't log in")
    @UserWithoutPermissions
    void testLogin_noPermissions() {
        final LoginStatus result;

        result = service.login("admin", "1234");

        Assertions.assertFalse(result.getLogged());
    }

    @Test
    @DisplayName("An existing user with valid password logs in")
    @ValidUser
    void testLogin_valid() {
        final LoginStatus result;

        result = service.login("admin", "1234");

        Assertions.assertTrue(result.getLogged());
    }

    @Test
    @DisplayName("A valid login returns all the data")
    @ValidUser
    void testLogin_valid_data() {
        final LoginStatus result;

        result = service.login("admin", "1234");

        Assertions.assertEquals("admin", result.getUsername());
        Assertions.assertTrue(result.getToken()
            .length() > 0);
    }

}
