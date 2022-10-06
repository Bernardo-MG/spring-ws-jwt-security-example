
package com.bernardomg.example.ws.security.jwt.test.auth.jwt.processor.unit;

import java.nio.charset.Charset;
import java.util.concurrent.TimeUnit;

import javax.crypto.SecretKey;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.bernardomg.example.ws.security.jwt.auth.jwt.token.JwtTokenProvider;
import com.bernardomg.example.ws.security.jwt.auth.jwt.token.JwtTokenValidator;
import com.bernardomg.example.ws.security.jwt.auth.token.TokenProvider;

import io.jsonwebtoken.security.Keys;

@DisplayName("JWT token processor - has expired")
public class TestJwtTokenProcessorHasExpired {

    private final TokenProvider     provider;

    private final JwtTokenValidator validator;

    public TestJwtTokenProcessorHasExpired() {
        super();

        final SecretKey key;

        key = Keys.hmacShaKeyFor(
            "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
                .getBytes(Charset.forName("UTF-8")));

        provider = new JwtTokenProvider(key, 1);
        validator = new JwtTokenValidator(key);
    }

    @Test
    @DisplayName("A new token is not expired")
    public void testHasExpired_fromGeneratedToken() {
        final String  token;
        final Boolean expired;

        token = provider.generateToken("subject");
        expired = validator.hasExpired(token);

        Assertions.assertFalse(expired);
    }

    @Test
    @DisplayName("An expired token is identified as such")
    public void testHasExpired_fromGeneratedToken_expired() throws InterruptedException {
        final String  token;
        final Boolean expired;

        token = provider.generateToken("subject");

        TimeUnit.SECONDS.sleep(Double.valueOf(1.5)
            .longValue());

        expired = validator.hasExpired(token);

        Assertions.assertTrue(expired);
    }

}
