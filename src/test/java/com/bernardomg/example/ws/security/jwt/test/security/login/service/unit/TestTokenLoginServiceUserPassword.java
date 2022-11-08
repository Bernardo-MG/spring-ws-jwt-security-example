
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
import com.bernardomg.example.ws.security.jwt.security.login.model.TokenLoginStatus;
import com.bernardomg.example.ws.security.jwt.security.login.service.TokenLoginService;
import com.bernardomg.example.ws.security.jwt.security.token.TokenProvider;

@DisplayName("Basic login service - password validation")
public class TestTokenLoginServiceUserPassword {

    public TestTokenLoginServiceUserPassword() {
        super();
    }

    @Test
    @DisplayName("Doesn't log in with an invalid password")
    public void testLogIn_Invalid() {
        final LoginStatus status;

        status = getService(false).login("admin", "1234");

        Assertions.assertFalse((status instanceof TokenLoginStatus));

        Assertions.assertFalse(status.getLogged());
        Assertions.assertEquals("admin", status.getUsername());
    }

    @Test
    @DisplayName("Logs in with a valid password")
    public void testLogIn_Valid() {
        final LoginStatus status;

        status = getService(true).login("admin", "1234");

        Assertions.assertInstanceOf(TokenLoginStatus.class, status);

        Assertions.assertTrue(status.getLogged());
        Assertions.assertEquals("admin", status.getUsername());
        Assertions.assertEquals("token", ((TokenLoginStatus) status).getToken());
    }

    private final TokenLoginService getService(final Boolean match) {
        final UserDetailsService userDetService;
        final PasswordEncoder    passEncoder;
        final TokenProvider      tokenProvider;
        final UserDetails        user;

        user = new User("username", "password", true, true, true, true, Collections.emptyList());

        userDetService = Mockito.mock(UserDetailsService.class);
        Mockito.when(userDetService.loadUserByUsername(ArgumentMatchers.anyString()))
            .thenReturn(user);

        passEncoder = Mockito.mock(PasswordEncoder.class);
        Mockito.when(passEncoder.matches(ArgumentMatchers.anyString(), ArgumentMatchers.anyString()))
            .thenReturn(match);

        tokenProvider = Mockito.mock(TokenProvider.class);
        Mockito.when(tokenProvider.generateToken(ArgumentMatchers.anyString()))
            .thenReturn("token");

        return new TokenLoginService(userDetService, passEncoder, tokenProvider);
    }

}
