
package com.bernardomg.example.spring.security.ws.jwt.test.encoding.jjwt.config;

import java.nio.charset.Charset;

import javax.crypto.SecretKey;

import io.jsonwebtoken.security.Keys;

public final class TokenConstants {

    public static final SecretKey KEY     = Keys.hmacShaKeyFor(
        "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
            .getBytes(Charset.forName("UTF-8")));

    public static final String    SUBJECT = "subject";

    private TokenConstants() {
        super();
    }

}
