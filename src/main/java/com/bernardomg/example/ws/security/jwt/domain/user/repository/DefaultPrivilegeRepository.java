
package com.bernardomg.example.ws.security.jwt.domain.user.repository;

import java.util.Collection;

import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.core.namedparam.SqlParameterSource;
import org.springframework.stereotype.Repository;

import com.bernardomg.example.ws.security.jwt.domain.entity.Privilege;

import lombok.AllArgsConstructor;

/**
 * Default implementation of the privilege repository.
 *
 * @author Bernardo Mart&iacute;nez Garrido
 *
 */
@Repository
@AllArgsConstructor
public final class DefaultPrivilegeRepository implements PrivilegeRepository {

    /**
     * JDBC template for running queries.
     */
    private final NamedParameterJdbcTemplate jdbcTemplate;

    /**
     * Query for finding the privileges of a user.
     */
    private final String                     queryForUser = "SELECT p.name FROM privileges p LEFT JOIN role_privileges rp ON p.id = rp.role_id LEFT JOIN roles r ON r.id = rp.role_id LEFT JOIN USER_ROLES ur ON r.id = ur.role_id LEFT JOIN users u ON u.id = ur.user_id WHERE u.id = :id";

    @Override
    public final Collection<Privilege> findForUser(final Long id) {
        final SqlParameterSource namedParameters;

        namedParameters = new MapSqlParameterSource().addValue("id", id);
        return jdbcTemplate.query(queryForUser, namedParameters, new PrivilegeRowRowMapper());
    }

}
