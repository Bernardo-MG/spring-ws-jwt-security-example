
package com.bernardomg.example.ws.security.jwt.resource.auth.login.service;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.bernardomg.example.ws.security.jwt.resource.auth.login.model.UserForm;
import com.bernardomg.example.ws.security.jwt.resource.auth.util.JwtTokenUtil;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@AllArgsConstructor
@Slf4j
public final class DefaultLoginService implements LoginService {

    private final JwtTokenUtil       jwtTokenUtil;

    private final PasswordEncoder    passwordEncoder;

    private final UserDetailsService service;

    @Override
    public final String login(final String username, final String password) {
        return jwtTokenUtil.generateToken(username);
    }

    private final UserForm toUser(final UserDetails details) {
        final UserForm user;

        user = new UserForm();
        user.setUsername(details.getUsername());

        return user;
    }

}
