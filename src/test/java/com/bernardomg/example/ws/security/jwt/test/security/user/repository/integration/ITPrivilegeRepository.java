
package com.bernardomg.example.ws.security.jwt.test.security.user.repository.integration;

import java.util.Collection;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.jdbc.Sql;

import com.bernardomg.example.ws.security.jwt.security.user.model.PersistentPrivilege;
import com.bernardomg.example.ws.security.jwt.security.user.repository.PrivilegeRepository;
import com.bernardomg.example.ws.security.jwt.test.config.annotation.IntegrationTest;

import liquibase.repackaged.org.apache.commons.collections4.IterableUtils;

@IntegrationTest
@DisplayName("Privilege repository")
@Sql({ "/db/queries/user/single.sql", "/db/queries/security/default_role.sql" })
public class ITPrivilegeRepository {

    @Autowired
    private PrivilegeRepository repository;

    public ITPrivilegeRepository() {
        super();
    }

    @Test
    @DisplayName("Returns all the privileges for a user")
    public void testFindForUser_Count() {
        final Iterable<PersistentPrivilege> result;

        result = repository.findForUser(1L);

        Assertions.assertEquals(4, IterableUtils.size(result));
    }

    @Test
    @DisplayName("Returns all the data for the privileges of a user")
    public void testFindForUser_Data() {
        final Collection<PersistentPrivilege> result;
        final Collection<String>              privileges;

        result = repository.findForUser(1L);
        privileges = result.stream()
            .map(PersistentPrivilege::getName)
            .collect(Collectors.toList());

        Assertions.assertTrue(privileges.contains("CREATE_DATA"));
        Assertions.assertTrue(privileges.contains("READ_DATA"));
        Assertions.assertTrue(privileges.contains("UPDATE_DATA"));
        Assertions.assertTrue(privileges.contains("DELETE_DATA"));
    }

    @Test
    @DisplayName("Returns no privileges for a not existing user")
    public void testFindForUser_notExisting() {
        final Iterable<PersistentPrivilege> result;

        result = repository.findForUser(-1L);

        Assertions.assertEquals(0, IterableUtils.size(result));
    }

}
