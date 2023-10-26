
package com.bernardomg.example.spring.security.ws.jwt.security.jwt.web.authentication;

import java.util.Objects;
import java.util.Optional;

import javax.crypto.SecretKey;

import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;

import com.bernardomg.example.spring.security.ws.jwt.security.jwt.token.JjwtTokenDecoder;
import com.bernardomg.example.spring.security.ws.jwt.security.jwt.token.JjwtTokenValidator;
import com.bernardomg.example.spring.security.ws.jwt.security.jwt.token.TokenDecoder;
import com.bernardomg.example.spring.security.ws.jwt.security.jwt.token.TokenValidator;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public final class JwtAuthenticationConverter implements AuthenticationConverter {

    /**
     * Token header identifier. This is added before the token to tell which kind of token it is. Used to make sure the
     * authentication header is valid.
     */
    private static final String      TOKEN_HEADER_IDENTIFIER = "Bearer";

    /**
     * Token decoder. Required to acquire the subject.
     */
    private final TokenDecoder       tokenDecoder;

    /**
     * Token validator. Expired tokens are rejected.
     */
    private final TokenValidator     tokenValidator;

    /**
     * User details service. Gives access to the user, to validate the token against it.
     */
    private final UserDetailsService userDetailsService;

    /**
     * Constructs an authentication converter with the received arguments.
     *
     * @param userDetService
     *            user details service
     * @param key
     *            secret key for encoding JWT tokens
     */
    public JwtAuthenticationConverter(final UserDetailsService userDetService, final SecretKey key) {
        super();

        tokenDecoder = new JjwtTokenDecoder(key);
        tokenValidator = new JjwtTokenValidator(tokenDecoder);

        userDetailsService = Objects.requireNonNull(userDetService);
    }

    @Override
    public final Authentication convert(final HttpServletRequest request) {
        final Optional<String> token;
        final String           subject;
        final Authentication   authentication;
        UserDetails            userDetails;

        log.debug("Authenticating {} request to {}", request.getMethod(), request.getServletPath());

        token = getToken(request);

        if (token.isEmpty()) {
            // Missing header
            log.debug("Missing authorization token");
            authentication = null;
        } else if (!tokenValidator.hasExpired(token.get())) {
            // Token not expired
            // Will load a new authentication from the token

            // Takes subject from the token
            subject = tokenDecoder.decode(token.get())
                .getSubject();
            try {
                userDetails = userDetailsService.loadUserByUsername(subject);
            } catch (final UsernameNotFoundException e) {
                userDetails = null;
            }

            if (userDetails == null) {
                log.debug("User {} not found", subject);
                authentication = null;
            } else if (isValid(userDetails)) {
                // Valid user
                log.debug("Valid user {}. Preparing authentication", subject);
                authentication = getAuthentication(userDetails, request, token.get());
            } else {
                log.debug("Invalid user {}", subject);
                authentication = null;
            }
        } else {
            log.debug("Expired token {}", token.get());
            authentication = null;
        }

        return authentication;
    }

    /**
     * Returns an {@link UsernamePasswordAuthenticationToken} created from the user and request.
     *
     * @param userDetails
     *            user for the authentication
     * @param request
     *            request details for the authentication
     * @param token
     *            parsed security token
     * @return an authentication object
     */
    private final Authentication getAuthentication(final UserDetails userDetails, final HttpServletRequest request,
            final String token) {
        final AbstractAuthenticationToken authenticationToken;
        final WebAuthenticationDetails    details;

        authenticationToken = new UsernamePasswordAuthenticationToken(userDetails, token, userDetails.getAuthorities());

        // Load web details
        details = new WebAuthenticationDetailsSource().buildDetails(request);
        authenticationToken.setDetails(details);

        return authenticationToken;
    }

    /**
     * Takes the token from the authorization header. This is expected to be something like
     * {@code Authorization: Bearer [token]}.
     *
     * @param request
     *            request containing the header with the token
     * @return the token if found, or an empty {@code Optional} otherwise
     */
    private final Optional<String> getToken(final HttpServletRequest request) {
        final String           header;
        final Optional<String> token;

        header = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (header == null) {
            // No token received
            token = Optional.empty();
            log.warn("Missing authorization header, can't return token", header);
        } else if (header.trim()
            .startsWith(TOKEN_HEADER_IDENTIFIER + " ")) {
            // Token received
            // Take it by removing the identifier
            // TODO: Should be case insensitive
            token = Optional.of(header.substring(TOKEN_HEADER_IDENTIFIER.length())
                .trim());
        } else {
            // Invalid token received
            token = Optional.empty();
            log.warn("Authorization header {} has an invalid structure, can't return token", header);
        }

        return token;
    }

    /**
     * Checks if the user is valid. This means it has no flag marking it as not usable.
     *
     * @param userDetails
     *            user the check
     * @return {@code true} if the user is valid, {@code false} otherwise
     */
    private final boolean isValid(final UserDetails userDetails) {
        return userDetails.isAccountNonExpired() && userDetails.isAccountNonLocked()
                && userDetails.isCredentialsNonExpired() && userDetails.isEnabled();
    }
}
