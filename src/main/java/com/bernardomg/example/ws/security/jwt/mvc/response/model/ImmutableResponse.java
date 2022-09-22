
package com.bernardomg.example.ws.security.jwt.mvc.response.model;

import lombok.Data;
import lombok.NonNull;

/**
 * Immutable implementation of the response.
 *
 * @author Bernardo Mart&iacute;nez Garrido
 *
 * @param <T>
 *            response content type
 */
@Data
public class ImmutableResponse<T> implements Response<T> {

    /**
     * Response content.
     */
    private final T content;

    /**
     * Default constructor.
     */
    public ImmutableResponse() {
        super();

        content = null;
    }

    /**
     * Constructs a response with the specified content.
     *
     * @param cont
     *            content
     */
    public ImmutableResponse(@NonNull final T cont) {
        super();

        content = cont;
    }

}
