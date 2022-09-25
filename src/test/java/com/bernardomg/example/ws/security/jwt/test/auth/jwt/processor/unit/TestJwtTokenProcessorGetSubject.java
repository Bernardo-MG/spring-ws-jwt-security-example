
package com.bernardomg.example.ws.security.jwt.test.auth.jwt.processor.unit;

import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import com.bernardomg.example.ws.security.jwt.auth.jwt.processor.JwtTokenProcessor;
import com.bernardomg.example.ws.security.jwt.auth.jwt.processor.TokenProcessor;

import io.jsonwebtoken.ExpiredJwtException;

@DisplayName("JWT token processor - get subject")
public class TestJwtTokenProcessorGetSubject {

    private final TokenProcessor processor = new JwtTokenProcessor(
        "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890", 2);

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

    @Test
    @DisplayName("Recovering the subject from an expired token generates an exception")
    public void test_getSubject_fromGeneratedToken_expired() throws InterruptedException {
        final String     token;
        final Executable executable;

        token = processor.generateToken("subject");

        TimeUnit.SECONDS.sleep(Double.valueOf(2.5)
            .longValue());

        executable = () -> processor.getSubject(token);

        Assertions.assertThrows(ExpiredJwtException.class, executable);
    }

}
