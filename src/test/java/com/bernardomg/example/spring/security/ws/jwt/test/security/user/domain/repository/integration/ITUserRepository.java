
package com.bernardomg.example.spring.security.ws.jwt.test.security.user.domain.repository.integration;

import java.util.Optional;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.jdbc.Sql;

import com.bernardomg.example.spring.security.ws.jwt.security.user.domain.model.User;
import com.bernardomg.example.spring.security.ws.jwt.security.user.domain.repository.UserRepository;
import com.bernardomg.example.spring.security.ws.jwt.test.config.annotation.IntegrationTest;

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

        result = repository.findOne("admin");

        Assertions.assertThat(result)
            .isPresent();
        Assertions.assertThat("admin")
            .isEqualTo(result.get()
                .username());
    }

    @Test
    @DisplayName("Returns no data for a not existing username")
    public void testFindForUser_notExisting() {
        final Optional<User> result;

        result = repository.findOne("abc");

        Assertions.assertThat(result)
            .isEmpty();
    }

}
