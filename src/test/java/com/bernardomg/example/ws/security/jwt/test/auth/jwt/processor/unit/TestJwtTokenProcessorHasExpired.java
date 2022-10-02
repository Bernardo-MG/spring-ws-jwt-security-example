
package com.bernardomg.example.ws.security.jwt.test.auth.jwt.processor.unit;

import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.bernardomg.example.ws.security.jwt.auth.jwt.token.JwtTokenProcessor;

@DisplayName("JWT token processor - has expired")
public class TestJwtTokenProcessorHasExpired {

    private final JwtTokenProcessor processor = new JwtTokenProcessor(
        "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890", 1);

    public TestJwtTokenProcessorHasExpired() {
        super();
    }

    @Test
    @DisplayName("A new token is not expired")
    public void testHasExpired_fromGeneratedToken() {
        final String  token;
        final Boolean expired;

        token = processor.generateToken("subject");
        expired = processor.hasExpired(token);

        Assertions.assertFalse(expired);
    }

    @Test
    @DisplayName("An expired token is identified as such")
    public void testHasExpired_fromGeneratedToken_expired() throws InterruptedException {
        final String  token;
        final Boolean expired;

        token = processor.generateToken("subject");

        TimeUnit.SECONDS.sleep(Double.valueOf(1.5)
            .longValue());

        expired = processor.hasExpired(token);

        Assertions.assertTrue(expired);
    }

}
