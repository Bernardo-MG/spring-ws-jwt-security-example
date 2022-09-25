
package com.bernardomg.example.ws.security.jwt.test.auth.jwt.processor.unit;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.bernardomg.example.ws.security.jwt.auth.jwt.processor.JwtTokenProcessor;
import com.bernardomg.example.ws.security.jwt.auth.jwt.processor.TokenProcessor;

@DisplayName("JWT token processor - generate token")
public class TestJwtTokenProcessorGenerateToken {

    private final TokenProcessor processor = new JwtTokenProcessor(
        "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890", 1);

    public TestJwtTokenProcessorGenerateToken() {
        super();
    }

    @Test
    @DisplayName("Generates a token")
    public void test_generateToken() {
        final String token;

        token = processor.generateToken("subject");

        Assertions.assertFalse(token.isEmpty());
    }

}
