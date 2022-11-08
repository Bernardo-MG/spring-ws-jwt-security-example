
package com.bernardomg.example.ws.security.jwt.test.security.login.service.unit;

import java.util.Collections;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.bernardomg.example.ws.security.jwt.security.login.model.LoginStatus;
import com.bernardomg.example.ws.security.jwt.security.login.service.BasicLoginService;

@DisplayName("Basic login service - password validation")
public class TestBasicLoginServiceUserPassword {

    public TestBasicLoginServiceUserPassword() {
        super();
    }

    @Test
    @DisplayName("Doesn't log in with an invalid password")
    public void testLogIn_Invalid() {
        final LoginStatus status;

        status = getService(false).login("admin", "1234");

        Assertions.assertFalse(status.getLogged());
        Assertions.assertEquals("admin", status.getUsername());
    }

    @Test
    @DisplayName("Logs in with a valid password")
    public void testLogIn_Valid() {
        final LoginStatus status;

        status = getService(true).login("admin", "1234");

        Assertions.assertTrue(status.getLogged());
        Assertions.assertEquals("admin", status.getUsername());
    }

    private final BasicLoginService getService(final Boolean match) {
        final UserDetailsService userDetService;
        final PasswordEncoder    passEncoder;
        final UserDetails        user;

        user = new User("username", "password", true, true, true, true, Collections.emptyList());

        userDetService = Mockito.mock(UserDetailsService.class);
        Mockito.when(userDetService.loadUserByUsername(ArgumentMatchers.anyString()))
            .thenReturn(user);

        passEncoder = Mockito.mock(PasswordEncoder.class);
        Mockito.when(passEncoder.matches(ArgumentMatchers.anyString(), ArgumentMatchers.anyString()))
            .thenReturn(match);

        return new BasicLoginService(userDetService, passEncoder);
    }

}
