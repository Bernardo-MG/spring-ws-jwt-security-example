
package com.bernardomg.example.ws.security.jwt.test.auth.login.validation.integration;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.jdbc.Sql;

import com.bernardomg.example.ws.security.jwt.auth.login.validation.LoginValidator;
import com.bernardomg.example.ws.security.jwt.auth.login.validation.CredentialsLoginValidator;
import com.bernardomg.example.ws.security.jwt.test.config.annotation.IntegrationTest;

@IntegrationTest
@DisplayName("Credentials login validator")
@Sql({ "/db/queries/user/single.sql", "/db/queries/role/single.sql", "/db/queries/privilege/multiple.sql",
        "/db/queries/relationship/role_privilege.sql", "/db/queries/relationship/user_role.sql" })
public class ITCredentialsLoginValidator {

    private final LoginValidator validator;

    @Autowired
    public ITCredentialsLoginValidator(final UserDetailsService userDetsService,
            final PasswordEncoder passEncoder) {
        super();

        validator = new CredentialsLoginValidator(userDetsService, passEncoder);
    }

    @Test
    @DisplayName("An existing user with invalid password is invalid")
    public final void testLogin_invalidPassword() {
        final Boolean valid;

        valid = validator.isValid("admin", "abc");

        Assertions.assertFalse(valid);
    }

    @Test
    @DisplayName("A not existing user is invalid")
    public final void testLogin_notExisting() {
        final Boolean valid;

        valid = validator.isValid("abc", "1234");

        Assertions.assertFalse(valid);
    }

    @Test
    @DisplayName("An existing user with valid password is valid")
    public final void testLogin_valid() {
        final Boolean valid;

        valid = validator.isValid("admin", "1234");

        Assertions.assertTrue(valid);
    }

}
