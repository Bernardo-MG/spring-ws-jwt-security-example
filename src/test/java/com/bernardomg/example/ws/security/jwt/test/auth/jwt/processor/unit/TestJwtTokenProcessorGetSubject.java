
package com.bernardomg.example.ws.security.jwt.test.auth.jwt.processor.unit;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.bernardomg.example.ws.security.jwt.auth.jwt.processor.JwtTokenProcessor;
import com.bernardomg.example.ws.security.jwt.auth.jwt.processor.TokenProcessor;

@DisplayName("JWT token processor - get subject")
public class TestJwtTokenProcessorGetSubject {

    private final TokenProcessor processor = new JwtTokenProcessor(
        "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890", 10000);

    public TestJwtTokenProcessorGetSubject() {
        super();
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

}
