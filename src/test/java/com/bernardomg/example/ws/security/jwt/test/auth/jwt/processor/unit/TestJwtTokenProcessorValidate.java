
package com.bernardomg.example.ws.security.jwt.test.auth.jwt.processor.unit;

import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.bernardomg.example.ws.security.jwt.auth.jwt.processor.JwtTokenProcessor;

@DisplayName("JWT token processor - validate")
public class TestJwtTokenProcessorValidate {

    private final JwtTokenProcessor processor = new JwtTokenProcessor(
        "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890", 1);

    public TestJwtTokenProcessorValidate() {
        super();
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
    @DisplayName("Can't validate an expired token")
    public void test_validate_fromGeneratedToken_expired() throws InterruptedException {
        final String  token;
        final Boolean valid;

        token = processor.generateToken("subject");

        TimeUnit.SECONDS.sleep(Double.valueOf(1.5)
            .longValue());

        valid = processor.validate(token, "abc");

        Assertions.assertFalse(valid);
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
