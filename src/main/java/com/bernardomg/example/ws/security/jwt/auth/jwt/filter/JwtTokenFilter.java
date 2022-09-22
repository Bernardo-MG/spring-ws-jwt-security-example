
package com.bernardomg.example.ws.security.jwt.auth.jwt.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.bernardomg.example.ws.security.jwt.auth.jwt.processor.TokenProcessor;

import io.jsonwebtoken.ExpiredJwtException;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Component
@AllArgsConstructor
@Slf4j
public class JwtTokenFilter extends OncePerRequestFilter {

    private final TokenProcessor     tokenProcessor;

    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(final HttpServletRequest request, final HttpServletResponse response,
            final FilterChain chain) throws ServletException, IOException {
        final String                              requestTokenHeader;
        final String                              jwtToken;
        String                                    username;
        final UserDetails                         userDetails;
        final UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken;

        requestTokenHeader = request.getHeader("Authorization");

        if (requestTokenHeader == null) {
            // Missing header
            log.debug("Missing authorization header");
        } else {
            // JWT Token is in the form "Bearer token". Remove Bearer word and get
            // only the Token
            if (requestTokenHeader.startsWith("Bearer ")) {
                jwtToken = requestTokenHeader.substring(7);
                log.debug("Parsing token {}", jwtToken);
                try {
                    username = tokenProcessor.getSubject(jwtToken);
                } catch (final IllegalArgumentException e) {
                    username = null;
                    System.out.println("Unable to get JWT Token");
                } catch (final ExpiredJwtException e) {
                    username = null;
                    System.out.println("JWT Token has expired");
                }
            } else {
                username = null;
                jwtToken = null;
                log.warn("Authorization header '{}' does not begin with Bearer String", requestTokenHeader);
            }

            // Once we get the token validate it.
            if ((username != null) && (SecurityContextHolder.getContext()
                .getAuthentication() == null)) {

                userDetails = userDetailsService.loadUserByUsername(username);

                // if token is valid configure Spring Security to manually set
                // authentication
                if (tokenProcessor.validate(jwtToken, userDetails.getUsername())) {

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
