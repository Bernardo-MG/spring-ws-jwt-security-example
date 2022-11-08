
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
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.bernardomg.example.ws.security.jwt.security.login.model.LoginStatus;
import com.bernardomg.example.ws.security.jwt.security.login.model.TokenLoginStatus;
import com.bernardomg.example.ws.security.jwt.security.login.service.TokenLoginService;
import com.bernardomg.example.ws.security.jwt.security.token.TokenProvider;

@DisplayName("Token login service - login with various user status")
public class TestTokenLoginServiceUserStatus {

    public TestTokenLoginServiceUserStatus() {
        super();
    }

    @Test
    @DisplayName("Doesn't log in a expired user")
    public void testLogIn_AccountExpired() {
        final LoginStatus status;

        status = getServiceForAccountExpired().login("admin", "1234");

        Assertions.assertFalse((status instanceof TokenLoginStatus));

        Assertions.assertFalse(status.getLogged());
        Assertions.assertEquals("admin", status.getUsername());
    }

    @Test
    @DisplayName("Doesn't log in a user with expired credentials")
    public void testLogIn_CredentialsExpired() {
        final LoginStatus status;

        status = getServiceForCredentialsExpired().login("admin", "1234");

        Assertions.assertFalse((status instanceof TokenLoginStatus));

        Assertions.assertFalse(status.getLogged());
        Assertions.assertEquals("admin", status.getUsername());
    }

    @Test
    @DisplayName("Doesn't log in a disabled user")
    public void testLogIn_Disabled() {
        final LoginStatus status;

        status = getServiceForDisabled().login("admin", "1234");

        Assertions.assertFalse((status instanceof TokenLoginStatus));

        Assertions.assertFalse(status.getLogged());
        Assertions.assertEquals("admin", status.getUsername());
    }

    @Test
    @DisplayName("Doesn't log in a locked user")
    public void testLogIn_Locked() {
        final LoginStatus status;

        status = getServiceForLocked().login("admin", "1234");

        Assertions.assertFalse((status instanceof TokenLoginStatus));

        Assertions.assertFalse(status.getLogged());
        Assertions.assertEquals("admin", status.getUsername());
    }

    @Test
    @DisplayName("Doesn't log in a not existing user")
    public void testLogIn_NotExisting() {
        final LoginStatus status;

        status = getServiceForNotExisting().login("admin", "1234");

        Assertions.assertFalse((status instanceof TokenLoginStatus));

        Assertions.assertFalse(status.getLogged());
        Assertions.assertEquals("admin", status.getUsername());
    }

    @Test
    @DisplayName("Logs in with a valid user")
    public void testLogIn_Valid() {
        final LoginStatus status;

        status = getServiceForValid().login("admin", "1234");

        Assertions.assertTrue(status.getLogged());
        Assertions.assertEquals("admin", status.getUsername());
        Assertions.assertEquals("token", ((TokenLoginStatus) status).getToken());
    }

    private final TokenLoginService getService(final UserDetails user) {
        final UserDetailsService userDetService;
        final PasswordEncoder    passEncoder;
        final TokenProvider      tokenProvider;

        userDetService = Mockito.mock(UserDetailsService.class);
        Mockito.when(userDetService.loadUserByUsername(ArgumentMatchers.anyString()))
            .thenReturn(user);

        passEncoder = Mockito.mock(PasswordEncoder.class);
        Mockito.when(passEncoder.matches(ArgumentMatchers.anyString(), ArgumentMatchers.anyString()))
            .thenReturn(true);

        tokenProvider = Mockito.mock(TokenProvider.class);
        Mockito.when(tokenProvider.generateToken(ArgumentMatchers.anyString()))
            .thenReturn("token");

        return new TokenLoginService(userDetService, passEncoder, tokenProvider);
    }

    private final TokenLoginService getServiceForAccountExpired() {
        final UserDetails user;

        user = new User("username", "password", true, false, true, true, Collections.emptyList());

        return getService(user);
    }

    private final TokenLoginService getServiceForCredentialsExpired() {
        final UserDetails user;

        user = new User("username", "password", true, true, false, true, Collections.emptyList());

        return getService(user);
    }

    private final TokenLoginService getServiceForDisabled() {
        final UserDetails user;

        user = new User("username", "password", false, true, true, true, Collections.emptyList());

        return getService(user);
    }

    private final TokenLoginService getServiceForLocked() {
        final UserDetails user;

        user = new User("username", "password", true, true, false, true, Collections.emptyList());

        return getService(user);
    }

    private final TokenLoginService getServiceForNotExisting() {
        final UserDetailsService userDetService;
        final PasswordEncoder    passEncoder;
        final TokenProvider      tokenProvider;

        userDetService = Mockito.mock(UserDetailsService.class);
        Mockito.when(userDetService.loadUserByUsername(ArgumentMatchers.anyString()))
            .thenThrow(UsernameNotFoundException.class);

        passEncoder = Mockito.mock(PasswordEncoder.class);

        tokenProvider = Mockito.mock(TokenProvider.class);
        Mockito.when(tokenProvider.generateToken(ArgumentMatchers.anyString()))
            .thenReturn("token");

        return new TokenLoginService(userDetService, passEncoder, tokenProvider);
    }

    private final TokenLoginService getServiceForValid() {
        final UserDetails user;

        user = new User("username", "password", true, true, true, true, Collections.emptyList());

        return getService(user);
    }

}
