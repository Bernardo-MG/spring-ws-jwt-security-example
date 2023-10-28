
package com.bernardomg.example.spring.security.ws.jwt.security.authentication;

import java.util.Objects;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

public final class DefaultAuthenticationManager implements AuthenticationManager {

    final UserDetailsService userDetailsService;

    public DefaultAuthenticationManager(final UserDetailsService userDetailsServ) {
        super();

        userDetailsService = Objects.requireNonNull(userDetailsServ);
    }

    @Override
    public final Authentication authenticate(final Authentication authentication) throws AuthenticationException {
        final UserDetails userDetails;

        userDetails = userDetailsService.loadUserByUsername(authentication.getName());

        return UsernamePasswordAuthenticationToken.authenticated(userDetails, authentication.getCredentials(),
            userDetails.getAuthorities());
    }

}
