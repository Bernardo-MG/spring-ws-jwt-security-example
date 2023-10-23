
package com.bernardomg.example.spring.security.ws.jwt.test.security.jwt.token.unit;

import java.time.LocalDateTime;

import org.assertj.core.api.Assertions;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.bernardomg.example.spring.security.ws.jwt.security.jwt.token.ImmutableJwtTokenData;
import com.bernardomg.example.spring.security.ws.jwt.security.jwt.token.JjwtTokenDecoder;
import com.bernardomg.example.spring.security.ws.jwt.security.jwt.token.JjwtTokenEncoder;
import com.bernardomg.example.spring.security.ws.jwt.security.jwt.token.JwtTokenData;
import com.bernardomg.example.spring.security.ws.jwt.security.jwt.token.TokenDecoder;
import com.bernardomg.example.spring.security.ws.jwt.security.jwt.token.TokenEncoder;
import com.bernardomg.example.spring.security.ws.jwt.test.security.jwt.token.config.TokenConstants;

import io.jsonwebtoken.ExpiredJwtException;

@DisplayName("JjwtTokenEncoder - get subject")
class TestJjwtTokenEncoderGetSubject {

    private final TokenDecoder decoder;

    private final TokenEncoder encoder;

    public TestJjwtTokenEncoderGetSubject() {
        super();

        encoder = new JjwtTokenEncoder(TokenConstants.KEY);
        decoder = new JjwtTokenDecoder(TokenConstants.KEY);
    }

    @Test
    @DisplayName("Recovers the subject from a token")
    void testGetSubject_fromGeneratedToken() {
        final String       token;
        final String       subject;
        final JwtTokenData data;

        data = ImmutableJwtTokenData.builder()
            .withSubject("subject")
            .build();

        token = encoder.encode(data);
        subject = decoder.decode(token)
            .getSubject();

        Assertions.assertThat(subject)
            .isEqualTo("subject");
    }

    @Test
    @DisplayName("Recovering the subject from an expired token generates an exception")
    void testGetSubject_fromGeneratedToken_expired() throws InterruptedException {
        final String           token;
        final ThrowingCallable executable;
        final JwtTokenData     data;

        data = ImmutableJwtTokenData.builder()
            .withSubject("subject")
            .withExpiration(LocalDateTime.now()
                .plusSeconds(-1))
            .build();

        token = encoder.encode(data);

        // TODO: This is a test for the decoder, test it
        executable = () -> decoder.decode(token);

        Assertions.assertThatThrownBy(executable)
            .isInstanceOf(ExpiredJwtException.class);
    }

}