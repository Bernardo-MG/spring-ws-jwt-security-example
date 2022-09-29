
package com.bernardomg.example.ws.security.jwt.test.auth.user.repository.integration;

import java.util.Collection;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.jdbc.Sql;

import com.bernardomg.example.ws.security.jwt.auth.user.domain.Privilege;
import com.bernardomg.example.ws.security.jwt.auth.user.repository.PrivilegeRepository;
import com.bernardomg.example.ws.security.jwt.test.config.annotation.IntegrationTest;

import liquibase.repackaged.org.apache.commons.collections4.IterableUtils;

@IntegrationTest
@DisplayName("Privilege repository")
@Sql({ "/db/queries/user/single.sql", "/db/queries/role/single.sql", "/db/queries/privilege/multiple.sql",
        "/db/queries/relationship/role_privilege.sql", "/db/queries/relationship/user_role.sql" })
public class ITPrivilegeRepository {

    @Autowired
    private PrivilegeRepository repository;

    public ITPrivilegeRepository() {
        super();
    }

    @Test
    @DisplayName("Returns all the privileges for a user")
    public void testFindForUser_Count() {
        final Iterable<? extends Privilege> result;

        result = repository.findForUser(1L);

        Assertions.assertEquals(3, IterableUtils.size(result));
    }

    @Test
    @DisplayName("Returns all the data for the privileges of a user")
    public void testFindForUser_Data() {
        final Collection<? extends Privilege> result;
        final Collection<String>              privileges;

        result = repository.findForUser(1L);
        privileges = result.stream()
            .map(Privilege::getName)
            .collect(Collectors.toList());

        Assertions.assertTrue(privileges.contains("CREATE_USER"));
        Assertions.assertTrue(privileges.contains("READ_USER"));
        Assertions.assertTrue(privileges.contains("UPDATE_USER"));
    }

    @Test
    @DisplayName("Returns no privileges for a not existing user")
    public void testFindForUser_notExisting() {
        final Iterable<? extends Privilege> result;

        result = repository.findForUser(-1L);

        Assertions.assertEquals(0, IterableUtils.size(result));
    }

}
