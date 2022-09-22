
package com.bernardomg.example.ws.security.jwt.mvc.error.model;

import lombok.Data;
import lombok.NonNull;

/**
 * Immutable failure object.
 *
 * @author Bernardo Mart&iacute;nez Garrido
 *
 */
@Data
public class ImmutableFailure implements Failure {

    @NonNull
    private final String message;

}
