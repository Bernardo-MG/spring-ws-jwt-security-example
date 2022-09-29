
package com.bernardomg.example.ws.security.jwt.test.domain.user.repository.integration;

import java.util.Optional;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.jdbc.Sql;

import com.bernardomg.example.ws.security.jwt.domain.user.domain.User;
import com.bernardomg.example.ws.security.jwt.domain.user.repository.UserRepository;
import com.bernardomg.example.ws.security.jwt.test.config.annotation.IntegrationTest;

@IntegrationTest
@DisplayName("User repository")
@Sql({ "/db/queries/user/single.sql" })
public class ITUserRepository {

    @Autowired
    private UserRepository repository;

    public ITUserRepository() {
        super();
    }

    @Test
    @DisplayName("Returns the user for an existing username")
    public void testFindForUser_existing() {
        final Optional<User> result;

        result = repository.findOneByUsername("admin");

        Assertions.assertTrue(result.isPresent());
        Assertions.assertEquals("admin", result.get()
            .getUsername());
    }

    @Test
    @DisplayName("Returns no data for a not existing username")
    public void testFindForUser_notExisting() {
        final Optional<User> result;

        result = repository.findOneByUsername("abc");

        Assertions.assertFalse(result.isPresent());
    }

}
