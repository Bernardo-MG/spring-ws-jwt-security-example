
package com.bernardomg.example.spring.security.ws.jwt.test.login.integration.service;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import com.bernardomg.example.spring.security.ws.jwt.security.login.model.TokenLoginStatus;
import com.bernardomg.example.spring.security.ws.jwt.security.login.service.LoginService;
import com.bernardomg.example.spring.security.ws.jwt.test.config.annotation.IntegrationTest;
import com.bernardomg.example.spring.security.ws.jwt.test.security.authentication.jwt.token.config.TokenConstants;
import com.bernardomg.example.spring.security.ws.jwt.test.security.user.config.CredentialsExpiredUser;
import com.bernardomg.example.spring.security.ws.jwt.test.security.user.config.DisabledUser;
import com.bernardomg.example.spring.security.ws.jwt.test.security.user.config.ExpiredUser;
import com.bernardomg.example.spring.security.ws.jwt.test.security.user.config.LockedUser;
import com.bernardomg.example.spring.security.ws.jwt.test.security.user.config.UserWithoutPermissions;
import com.bernardomg.example.spring.security.ws.jwt.test.security.user.config.ValidUser;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;

@IntegrationTest
@DisplayName("Login service")
class ITLoginService {

    @Autowired
    private LoginService service;

    public ITLoginService() {
        super();
    }

    @Test
    @DisplayName("Logs in with a valid user, ignoring username case")
    @ValidUser
    void testLogin_case() {
        final TokenLoginStatus result;

        result = service.login("ADMIN", "1234");

        Assertions.assertThat(result.getLogged())
            .isTrue();
    }

    @Test
    @DisplayName("A user with credentials expired doesn't log in")
    @CredentialsExpiredUser
    void testLogin_credentialsExpired() {
        final TokenLoginStatus result;

        result = service.login("admin", "abc");

        Assertions.assertThat(result.getLogged())
            .isFalse();
    }

    @Test
    @DisplayName("A disbled user doesn't log in")
    @DisabledUser
    void testLogin_disabled() {
        final TokenLoginStatus result;

        result = service.login("admin", "abc");

        Assertions.assertThat(result.getLogged())
            .isFalse();
    }

    @Test
    @DisplayName("A disbled user doesn't log in")
    @ExpiredUser
    void testLogin_expired() {
        final TokenLoginStatus result;

        result = service.login("admin", "abc");

        Assertions.assertThat(result.getLogged())
            .isFalse();
    }

    @Test
    @DisplayName("An existing user with invalid password doesn't log in")
    @ValidUser
    void testLogin_invalidPassword() {
        final TokenLoginStatus result;

        result = service.login("admin", "abc");

        Assertions.assertThat(result.getLogged())
            .isFalse();
    }

    @Test
    @DisplayName("A disbled user doesn't log in")
    @LockedUser
    void testLogin_locked() {
        final TokenLoginStatus result;

        result = service.login("admin", "abc");

        Assertions.assertThat(result.getLogged())
            .isFalse();
    }

    @Test
    @DisplayName("A not existing user doesn't log in")
    void testLogin_noData() {
        final TokenLoginStatus result;

        result = service.login("admin", "abc");

        Assertions.assertThat(result.getLogged())
            .isFalse();
    }

    @Test
    @DisplayName("A user without permissions can't log in")
    @UserWithoutPermissions
    void testLogin_noPermissions() {
        final TokenLoginStatus result;

        result = service.login("admin", "1234");

        Assertions.assertThat(result.getLogged())
            .isFalse();
    }

    @Test
    @DisplayName("An existing user with valid password logs in")
    @ValidUser
    void testLogin_valid() {
        final TokenLoginStatus result;

        result = service.login("admin", "1234");

        Assertions.assertThat(result.getLogged())
            .isTrue();
    }

    @Test
    @DisplayName("A valid login returns all the data")
    @ValidUser
    void testLogin_valid_data() {
        final TokenLoginStatus result;

        result = service.login("admin", "1234");

        Assertions.assertThat(result.getUsername())
            .isEqualTo("admin");
        Assertions.assertThat(result.getToken())
            .isNotEmpty();
    }

    @Test
    @DisplayName("On a succesful login returns a valid JWT token")
    @ValidUser
    void testLogIn_Valid_JwtToken() {
        final TokenLoginStatus status;
        final JwtParser        parser;
        final Claims           claims;

        status = service.login("admin", "1234");

        parser = Jwts.parser()
            .verifyWith(TokenConstants.KEY)
            .build();

        claims = parser.parseSignedClaims(status.getToken())
            .getPayload();

        Assertions.assertThat(claims.getSubject())
            .isEqualTo("admin");
    }

}
