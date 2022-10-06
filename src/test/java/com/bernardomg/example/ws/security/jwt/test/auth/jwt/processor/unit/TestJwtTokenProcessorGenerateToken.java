
package com.bernardomg.example.ws.security.jwt.test.auth.jwt.processor.unit;

import java.nio.charset.Charset;

import javax.crypto.SecretKey;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.bernardomg.example.ws.security.jwt.auth.jwt.token.JwtTokenProvider;
import com.bernardomg.example.ws.security.jwt.auth.token.TokenProvider;

import io.jsonwebtoken.security.Keys;

@DisplayName("JWT token processor - generate token")
public class TestJwtTokenProcessorGenerateToken {

    private final TokenProvider provider;

    public TestJwtTokenProcessorGenerateToken() {
        super();

        final SecretKey key;

        key = Keys.hmacShaKeyFor(
            "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
                .getBytes(Charset.forName("UTF-8")));

        provider = new JwtTokenProvider(key, 1);
    }

    @Test
    @DisplayName("Generates a token")
    public void testGenerateToken() {
        final String token;

        token = provider.generateToken("subject");

        Assertions.assertFalse(token.isEmpty());
    }

}
