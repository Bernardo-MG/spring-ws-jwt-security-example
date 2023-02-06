
package com.bernardomg.example.spring.security.ws.jwt.security.token.model;

import lombok.Data;

@Data
public final class ImmutableToken implements Token {

    private final String token;

    public ImmutableToken(final String tk) {
        super();

        token = tk;
    }

}
