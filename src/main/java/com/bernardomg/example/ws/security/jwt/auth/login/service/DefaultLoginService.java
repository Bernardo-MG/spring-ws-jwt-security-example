
package com.bernardomg.example.ws.security.jwt.auth.login.service;

import org.springframework.stereotype.Service;

import com.bernardomg.example.ws.security.jwt.auth.login.model.DtoLoginStatus;
import com.bernardomg.example.ws.security.jwt.auth.login.model.LoginStatus;
import com.bernardomg.example.ws.security.jwt.auth.util.JwtTokenUtil;

import lombok.AllArgsConstructor;

@Service
@AllArgsConstructor
public final class DefaultLoginService implements LoginService {

    private final JwtTokenUtil jwtTokenUtil;

    @Override
    public final LoginStatus login(final String username, final String password) {
        final DtoLoginStatus status;
        final String         token;

        token = jwtTokenUtil.generateToken(username);

        status = new DtoLoginStatus();
        status.setToken(token);

        return status;
    }

}
