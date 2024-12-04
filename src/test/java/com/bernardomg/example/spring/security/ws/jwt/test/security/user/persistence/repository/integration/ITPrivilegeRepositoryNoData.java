
package com.bernardomg.example.spring.security.ws.jwt.test.security.user.persistence.repository.integration;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import com.bernardomg.example.spring.security.ws.jwt.security.user.persistence.model.PersistentPrivilege;
import com.bernardomg.example.spring.security.ws.jwt.security.user.persistence.repository.PrivilegeRepository;
import com.bernardomg.example.spring.security.ws.jwt.test.config.annotation.IntegrationTest;

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

        Assertions.assertThat(result)
            .isEmpty();
    }

}
