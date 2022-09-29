
package com.bernardomg.example.ws.security.jwt.test.domain.user.repository.integration;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.jdbc.Sql;

import com.bernardomg.example.ws.security.jwt.domain.entity.Privilege;
import com.bernardomg.example.ws.security.jwt.domain.user.repository.PrivilegeRepository;
import com.bernardomg.example.ws.security.jwt.test.config.annotation.IntegrationTest;

import liquibase.repackaged.org.apache.commons.collections4.IterableUtils;

@IntegrationTest
@DisplayName("Fee year repository - find all for year - full year")
@Sql({ "/db/queries/user/single.sql", "/db/queries/role/single.sql", "/db/queries/privilege/multiple.sql",
        "/db/queries/relationship/role_privilege.sql", "/db/queries/relationship/user_role.sql" })
public class ITPrivilegeRepository {

    @Autowired
    private PrivilegeRepository repository;

    public ITPrivilegeRepository() {
        super();
    }

    @Test
    @DisplayName("Returns all the entities")
    public void testGetAll_Count() {
        final Iterable<? extends Privilege> result;

        result = repository.findForUser(1L);

        Assertions.assertEquals(3, IterableUtils.size(result));
    }

}
