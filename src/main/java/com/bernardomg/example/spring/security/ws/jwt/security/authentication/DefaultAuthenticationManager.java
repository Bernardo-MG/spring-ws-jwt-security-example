
package com.bernardomg.example.spring.security.ws.jwt.security.authentication;

import java.util.Objects;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public final class DefaultAuthenticationManager implements AuthenticationManager {

    final UserDetailsService userDetailsService;

    public DefaultAuthenticationManager(final UserDetailsService userDetailsServ) {
        super();

        userDetailsService = Objects.requireNonNull(userDetailsServ);
    }

    @Override
    public final Authentication authenticate(final Authentication authentication) throws AuthenticationException {
        final UserDetails userDetails;

        try {
            userDetails = userDetailsService.loadUserByUsername(authentication.getName());
        } catch (final UsernameNotFoundException e) {
            throw new BadCredentialsException(String.format("User %s not found", authentication.getName()));
        }

        if (!userDetails.isEnabled()) {
            throw new DisabledException(String.format("User %s is disabled", authentication.getName()));
        }
        if (!userDetails.isAccountNonLocked()) {
            throw new DisabledException(String.format("User %s is locked", authentication.getName()));
        }
        if (!userDetails.isCredentialsNonExpired()) {
            throw new BadCredentialsException(
                String.format("User %s credentials are expired", authentication.getName()));
        }

        return UsernamePasswordAuthenticationToken.authenticated(userDetails, authentication.getCredentials(),
            userDetails.getAuthorities());
    }

}
