
package com.bernardomg.example.ws.security.jwt.domain.user.repository;

import java.util.Collection;

import com.bernardomg.example.ws.security.jwt.domain.user.domain.Privilege;

/**
 * Repository for privileges.
 *
 * @author Bernardo Mart&iacute;nez Garrido
 *
 */
public interface PrivilegeRepository {

    /**
     * Returns all the privileges for a user. This requires a join from the user up to the privileges.
     *
     * @param id
     *            user id
     * @return all the privileges for the user
     */
    public Collection<Privilege> findForUser(final Long id);

}
