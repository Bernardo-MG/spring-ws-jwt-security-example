
package com.bernardomg.example.spring.security.ws.jwt.test.security.token.unit;

import java.nio.charset.Charset;

import javax.crypto.SecretKey;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.bernardomg.example.spring.security.ws.jwt.security.jwt.token.JwtSubjectTokenEncoder;
import com.bernardomg.example.spring.security.ws.jwt.security.token.provider.TokenEncoder;

import io.jsonwebtoken.security.Keys;

@DisplayName("JWT token encoder - generate token")
public class TestJwtTokenEncoderGenerateToken {

    private final TokenEncoder<String> provider;

    public TestJwtTokenEncoderGenerateToken() {
        super();

        final SecretKey key;

        key = Keys.hmacShaKeyFor(
            "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
                .getBytes(Charset.forName("UTF-8")));

        provider = new JwtSubjectTokenEncoder(key, 1);
    }

    @Test
    @DisplayName("Generates a token")
    public void testGenerateToken() {
        final String token;

        token = provider.generateToken("subject");

        Assertions.assertFalse(token.isEmpty());
    }

}
