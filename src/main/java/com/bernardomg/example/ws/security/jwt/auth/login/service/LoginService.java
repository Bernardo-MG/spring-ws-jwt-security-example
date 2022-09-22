
package com.bernardomg.example.ws.security.jwt.auth.login.service;

import com.bernardomg.example.ws.security.jwt.auth.login.model.LoginStatus;

public interface LoginService {

    public LoginStatus login(final String username, final String password);

}
