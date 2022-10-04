
package com.bernardomg.example.ws.security.jwt.test.auth.user.repository.integration;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import com.bernardomg.example.ws.security.jwt.auth.user.model.PersistentPrivilege;
import com.bernardomg.example.ws.security.jwt.auth.user.repository.PrivilegeRepository;
import com.bernardomg.example.ws.security.jwt.test.config.annotation.IntegrationTest;

import liquibase.repackaged.org.apache.commons.collections4.IterableUtils;

@IntegrationTest
@DisplayName("Privilege repository - no data")
public class ITPrivilegeRepositoryNoData {

    @Autowired
    private PrivilegeRepository repository;

    public ITPrivilegeRepositoryNoData() {
        super();
    }

    @Test
    @DisplayName("Returns all the privileges for a user")
    public void testFindForUser_Count() {
        final Iterable<PersistentPrivilege> result;

        result = repository.findForUser(1L);

        Assertions.assertEquals(0, IterableUtils.size(result));
    }

}
