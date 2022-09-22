
package com.bernardomg.example.ws.security.jwt.auth.login.service;

import org.springframework.stereotype.Service;

import com.bernardomg.example.ws.security.jwt.auth.jwt.processor.TokenProcessor;
import com.bernardomg.example.ws.security.jwt.auth.login.model.DtoLoginStatus;
import com.bernardomg.example.ws.security.jwt.auth.login.model.LoginStatus;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@AllArgsConstructor
@Slf4j
public final class DefaultLoginService implements LoginService {

    private final TokenProcessor tokenProcessor;

    @Override
    public final LoginStatus login(final String username, final String password) {
        final DtoLoginStatus status;
        final String         token;

        log.trace("Generating token for {}", username);

        // TODO: Get user and check password

        token = tokenProcessor.generateToken(username);

        status = new DtoLoginStatus();
        status.setToken(token);

        return status;
    }

}
