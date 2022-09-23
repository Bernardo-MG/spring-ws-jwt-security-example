
package com.bernardomg.example.ws.security.jwt.auth.jwt.filter;

import java.io.IOException;
import java.util.Objects;
import java.util.Optional;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import com.bernardomg.example.ws.security.jwt.auth.jwt.processor.TokenProcessor;

import io.jsonwebtoken.ExpiredJwtException;
import lombok.extern.slf4j.Slf4j;

/**
 * JWT token filter.
 *
 * @author Bernardo Mart&iacute;nez Garrido
 *
 */
@Slf4j
public class JwtTokenFilter extends OncePerRequestFilter {

    private final TokenProcessor     tokenProcessor;

    private final UserDetailsService userDetailsService;

    public JwtTokenFilter(final UserDetailsService userDetService, final TokenProcessor processor) {
        super();

        userDetailsService = Objects.requireNonNull(userDetService);
        tokenProcessor = Objects.requireNonNull(processor);
    }

    /**
     * Returns the subject from a token.
     *
     * @param token
     *            the token to parse
     * @return the subject from the token if found, or an empty {@code Optional} otherwise
     */
    private final Optional<String> getSubject(final Optional<String> token) {
        Optional<String> subject;

        if (token.isPresent()) {
            log.debug("Parsing subject from token {}", token);
            try {
                subject = Optional.ofNullable(tokenProcessor.getSubject(token.get()));
            } catch (final IllegalArgumentException e) {
                subject = Optional.empty();
                log.warn("Unable to get JWT Token");
            } catch (final ExpiredJwtException e) {
                subject = Optional.empty();
                log.warn("JWT Token has expired");
            }
        } else {
            // No token received
            subject = Optional.empty();
        }

        return subject;
    }

    /**
     * Takes the token from the authorization header.
     *
     * @param header
     *            header with the token
     * @return the token if found, or an empty {@code Optional} otherwise
     */
    private final Optional<String> getToken(final String header) {
        final Optional<String> token;

        // JWT Token is in the form "Bearer token". Remove Bearer word and get
        // only the Token
        if (header.startsWith("Bearer ")) {
            token = Optional.of(header.substring(7));
        } else {
            token = Optional.empty();
            log.warn("Authorization header '{}' does not begin with Bearer String", header);
        }

        return token;
    }

    @Override
    protected void doFilterInternal(final HttpServletRequest request, final HttpServletResponse response,
            final FilterChain chain) throws ServletException, IOException {
        final String                              requestTokenHeader;
        final Optional<String>                    token;
        final Optional<String>                    subject;
        final UserDetails                         userDetails;
        final UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken;

        requestTokenHeader = request.getHeader("Authorization");

        if (requestTokenHeader == null) {
            // Missing header
            log.debug("Missing authorization header");
        } else {
            token = getToken(requestTokenHeader);
            subject = getSubject(token);

            // Once we get the token validate it.
            if ((subject.isPresent()) && (SecurityContextHolder.getContext()
                .getAuthentication() == null)) {

                userDetails = userDetailsService.loadUserByUsername(subject.get());

                // if token is valid configure Spring Security to manually set
                // authentication
                if (tokenProcessor.validate(token.get(), userDetails.getUsername())) {
                    usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null,
                        userDetails.getAuthorities());
                    usernamePasswordAuthenticationToken
                        .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    // After setting the Authentication in the context, we specify
                    // that the current user is authenticated. So it passes the
                    // Spring Security Configurations successfully.
                    SecurityContextHolder.getContext()
                        .setAuthentication(usernamePasswordAuthenticationToken);
                }
            }
        }

        chain.doFilter(request, response);
    }

}
