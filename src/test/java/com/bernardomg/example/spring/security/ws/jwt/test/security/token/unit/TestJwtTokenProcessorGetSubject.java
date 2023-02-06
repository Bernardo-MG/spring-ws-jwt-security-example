
package com.bernardomg.example.spring.security.ws.jwt.test.security.token.unit;

import java.nio.charset.Charset;
import java.util.concurrent.TimeUnit;

import javax.crypto.SecretKey;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import com.bernardomg.example.spring.security.ws.jwt.security.jwt.token.JwtTokenProvider;
import com.bernardomg.example.spring.security.ws.jwt.security.jwt.token.JwtTokenValidator;
import com.bernardomg.example.spring.security.ws.jwt.security.token.provider.TokenProvider;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.security.Keys;

@DisplayName("JWT token processor - get subject")
public class TestJwtTokenProcessorGetSubject {

    private final TokenProvider     provider;

    private final JwtTokenValidator validator;

    public TestJwtTokenProcessorGetSubject() {
        super();

        final SecretKey key;

        key = Keys.hmacShaKeyFor(
            "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
                .getBytes(Charset.forName("UTF-8")));

        provider = new JwtTokenProvider(key, 1);
        validator = new JwtTokenValidator(key);
    }

    @Test
    @DisplayName("Recovers the subject from a token")
    public void testGetSubject_fromGeneratedToken() {
        final String token;
        final String subject;

        token = provider.generateToken("subject");
        subject = validator.getSubject(token);

        Assertions.assertEquals("subject", subject);
    }

    @Test
    @DisplayName("Recovering the subject from an expired token generates an exception")
    public void testGetSubject_fromGeneratedToken_expired() throws InterruptedException {
        final String     token;
        final Executable executable;

        token = provider.generateToken("subject");

        TimeUnit.SECONDS.sleep(Double.valueOf(2)
            .longValue());

        executable = () -> validator.getSubject(token);

        Assertions.assertThrows(ExpiredJwtException.class, executable);
    }

}
