
package com.bernardomg.example.ws.security.jwt.test.auth.jwt.processor.unit;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.bernardomg.example.ws.security.jwt.auth.jwt.processor.JwtTokenProcessor;
import com.bernardomg.example.ws.security.jwt.auth.jwt.processor.TokenProcessor;

@DisplayName("JWT token processor")
public class TestJwtTokenProcessor {

    private final TokenProcessor processor = new JwtTokenProcessor(
        "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890", 10000);

    public TestJwtTokenProcessor() {
        super();
    }

    @Test
    @DisplayName("Generates a token")
    public void test_generateToken() {
        final String token;

        token = processor.generateToken("subject");

        Assertions.assertFalse(token.isEmpty());
    }

    @Test
    @DisplayName("Recovers the subject from a token")
    public void test_getSubject_fromGeneratedToken() {
        final String token;
        final String subject;

        token = processor.generateToken("subject");
        subject = processor.getSubject(token);

        Assertions.assertEquals("subject", subject);
    }

    @Test
    @DisplayName("Validates a generated token")
    public void test_validate_fromGeneratedToken() {
        final String  token;
        final Boolean valid;

        token = processor.generateToken("subject");
        valid = processor.validate(token, "subject");

        Assertions.assertTrue(valid);
    }

    @Test
    @DisplayName("Can't validate a token with wrong subject")
    public void test_validate_fromGeneratedToken_wrongSubject() {
        final String  token;
        final Boolean valid;

        token = processor.generateToken("subject");
        valid = processor.validate(token, "abc");

        Assertions.assertFalse(valid);
    }

}
