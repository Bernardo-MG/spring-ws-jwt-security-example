
package com.bernardomg.example.spring.security.ws.jwt.test.security.token.unit;

import java.nio.charset.Charset;

import javax.crypto.SecretKey;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.bernardomg.example.spring.security.ws.jwt.security.jwt.token.JwtSubjectTokenEncoder;
import com.bernardomg.example.spring.security.ws.jwt.security.token.TokenEncoder;

import io.jsonwebtoken.security.Keys;

@DisplayName("JwtSubjectTokenEncoder - generate token")
public class TestJwtSubjectTokenEncoderGenerateToken {

    private final TokenEncoder<String> encoder;

    public TestJwtSubjectTokenEncoderGenerateToken() {
        super();

        final SecretKey key;

        key = Keys.hmacShaKeyFor(
            "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
                .getBytes(Charset.forName("UTF-8")));

        encoder = new JwtSubjectTokenEncoder(key, 1);
    }

    @Test
    @DisplayName("Encodes a token")
    public void testGenerateToken() {
        final String token;

        token = encoder.encode("subject");

        Assertions.assertFalse(token.isEmpty());
    }

}
