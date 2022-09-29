
package com.bernardomg.example.ws.security.jwt.domain.user.repository;

import java.sql.ResultSet;
import java.sql.SQLException;

import org.springframework.jdbc.core.RowMapper;

import com.bernardomg.example.ws.security.jwt.domain.user.domain.DtoPrivilege;
import com.bernardomg.example.ws.security.jwt.domain.user.domain.Privilege;

public final class PrivilegeRowRowMapper implements RowMapper<Privilege> {

    public PrivilegeRowRowMapper() {
        super();
    }

    @Override
    public final Privilege mapRow(final ResultSet rs, final int rowNum) throws SQLException {
        final DtoPrivilege privilege;

        try {

            privilege = new DtoPrivilege();
            privilege.setName(rs.getString("name"));
        } catch (final SQLException e) {
            // TODO: Handle better
            throw new RuntimeException(e);
        }

        return privilege;
    }

}
