
package com.bernardomg.example.ws.security.jwt.auth.login.service;

import org.springframework.stereotype.Service;

import com.bernardomg.example.ws.security.jwt.auth.util.JwtTokenUtil;

import lombok.AllArgsConstructor;

@Service
@AllArgsConstructor
public final class DefaultLoginService implements LoginService {

    private final JwtTokenUtil jwtTokenUtil;

    @Override
    public final String login(final String username, final String password) {
        return jwtTokenUtil.generateToken(username);
    }

}
