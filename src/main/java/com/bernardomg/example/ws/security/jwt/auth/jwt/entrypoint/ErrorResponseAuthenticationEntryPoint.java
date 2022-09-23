
package com.bernardomg.example.ws.security.jwt.auth.jwt.entrypoint;

import java.io.IOException;
import java.io.Serializable;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import com.bernardomg.example.ws.security.jwt.mvc.error.model.Failure;
import com.bernardomg.example.ws.security.jwt.mvc.response.model.ErrorResponse;
import com.bernardomg.example.ws.security.jwt.mvc.response.model.Response;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.extern.slf4j.Slf4j;

/**
 * Authentication entry point which returns an {@link ErrorResponse} on failure.
 *
 * @author Bernardo Mart&iacute;nez Garrido
 *
 */
@Slf4j
public final class ErrorResponseAuthenticationEntryPoint implements AuthenticationEntryPoint, Serializable {

    /**
     * Serialization ID.
     */
    private static final long serialVersionUID = 3481060353509546161L;

    /**
     * Default constructor.
     */
    public ErrorResponseAuthenticationEntryPoint() {
        super();
    }

    @Override
    public final void commence(final HttpServletRequest request, final HttpServletResponse response,
            final AuthenticationException authException) throws IOException, ServletException {
        final ErrorResponse resp;
        final Failure       error;

        log.debug("Authentication failure for path {}: {}", request.getServletPath(), authException.getMessage());

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        error = Failure.of("Unauthorized");
        resp = Response.error(error);

        final ObjectMapper mapper = new ObjectMapper();
        mapper.writeValue(response.getOutputStream(), resp);
    }

}
