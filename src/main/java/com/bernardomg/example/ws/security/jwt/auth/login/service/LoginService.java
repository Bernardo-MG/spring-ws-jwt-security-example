
package com.bernardomg.example.ws.security.jwt.auth.login.service;

import com.bernardomg.example.ws.security.jwt.auth.login.model.LoginStatus;

/**
 * Login service. Takes the user credentials and returns a token.
 *
 * @author Bernardo Mart&iacute;nez Garrido
 *
 */
public interface LoginService {

    /**
     * Receives credentials and returns the login status. If it was valid then it contains a token.
     *
     * @param username
     *            username to authenticate
     * @param password
     *            password to authenticate
     * @return login status
     */
    public LoginStatus login(final String username, final String password);

}
