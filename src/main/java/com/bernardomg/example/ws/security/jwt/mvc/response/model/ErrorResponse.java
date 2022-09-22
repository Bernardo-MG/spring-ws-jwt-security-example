
package com.bernardomg.example.ws.security.jwt.mvc.response.model;

import java.util.Collection;

import com.bernardomg.example.ws.security.jwt.mvc.error.model.Failure;

/**
 * Error response to the frontend.
 *
 * @author Bernardo Mart&iacute;nez Garrido
 */
public interface ErrorResponse {

    public Collection<? extends Failure> getErrors();

}
