
package com.bernardomg.example.ws.security.jwt.test.security.login.service.unit;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.bernardomg.example.ws.security.jwt.security.login.model.LoginStatus;
import com.bernardomg.example.ws.security.jwt.security.login.service.BasicLoginService;

@DisplayName("Basic login service - failure handling")
public class TestBasicLoginServiceUserFailure {

    public TestBasicLoginServiceUserFailure() {
        super();
    }

    @Test
    @DisplayName("When the user details service returns a null the login fails")
    public void testLogIn_NullUser() {
        final LoginStatus status;

        status = getServiceWithNullUser().login("admin", "1234");

        Assertions.assertFalse(status.getLogged());
        Assertions.assertEquals("admin", status.getUsername());
    }

    private final BasicLoginService getService(final UserDetails user) {
        final UserDetailsService userDetService;
        final PasswordEncoder    passEncoder;

        userDetService = Mockito.mock(UserDetailsService.class);
        Mockito.when(userDetService.loadUserByUsername(ArgumentMatchers.anyString()))
            .thenReturn(user);

        passEncoder = Mockito.mock(PasswordEncoder.class);
        Mockito.when(passEncoder.matches(ArgumentMatchers.anyString(), ArgumentMatchers.anyString()))
            .thenReturn(true);

        return new BasicLoginService(userDetService, passEncoder);
    }

    private final BasicLoginService getServiceWithNullUser() {
        return getService(null);
    }

}
