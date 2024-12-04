
package com.bernardomg.example.spring.security.ws.jwt.test.security.user.persistence.repository.integration;

import java.util.Collection;
import java.util.stream.Collectors;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import com.bernardomg.example.spring.security.ws.jwt.security.user.persistence.model.PersistentPrivilege;
import com.bernardomg.example.spring.security.ws.jwt.security.user.persistence.repository.PrivilegeRepository;
import com.bernardomg.example.spring.security.ws.jwt.test.config.annotation.IntegrationTest;
import com.bernardomg.example.spring.security.ws.jwt.test.security.user.config.ValidUser;

@IntegrationTest
@DisplayName("Privilege repository")
@ValidUser
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

        Assertions.assertThat(result)
            .hasSize(4);
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

        Assertions.assertThat(privileges)
            .contains("CREATE_DATA", "READ_DATA", "UPDATE_DATA", "DELETE_DATA");
    }

    @Test
    @DisplayName("Returns no privileges for a not existing user")
    public void testFindForUser_notExisting() {
        final Iterable<PersistentPrivilege> result;

        result = repository.findForUser(-1L);

        Assertions.assertThat(result)
            .isEmpty();
    }

}
