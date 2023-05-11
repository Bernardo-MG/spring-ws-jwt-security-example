
package com.bernardomg.example.spring.security.ws.jwt.security.token;

public interface TokenDecoder<T> {

    public T decode(final String token);

}
