
package com.bernardomg.example.spring.security.ws.jwt.test.security.authentication.jwt.token.unit;

import java.time.LocalDateTime;

import org.assertj.core.api.Assertions;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.bernardomg.example.spring.security.ws.jwt.security.authentication.jwt.token.ImmutableJwtTokenData;
import com.bernardomg.example.spring.security.ws.jwt.security.authentication.jwt.token.JjwtTokenDecoder;
import com.bernardomg.example.spring.security.ws.jwt.security.authentication.jwt.token.JjwtTokenEncoder;
import com.bernardomg.example.spring.security.ws.jwt.security.authentication.jwt.token.JwtTokenData;
import com.bernardomg.example.spring.security.ws.jwt.security.authentication.jwt.token.TokenDecoder;
import com.bernardomg.example.spring.security.ws.jwt.security.authentication.jwt.token.TokenEncoder;
import com.bernardomg.example.spring.security.ws.jwt.test.security.authentication.jwt.token.config.TokenConstants;

import io.jsonwebtoken.ExpiredJwtException;

@DisplayName("JjwtTokenEncoder - get subject")
class TestJjwtTokenEncoderGetSubject {

    private final TokenDecoder decoder = new JjwtTokenDecoder(TokenConstants.KEY);

    private final TokenEncoder encoder = new JjwtTokenEncoder(TokenConstants.KEY);

    @Test
    @DisplayName("Recovers the subject from a token")
    void testGetSubject_fromGeneratedToken() {
        final String       token;
        final String       subject;
        final JwtTokenData data;

        data = ImmutableJwtTokenData.builder()
            .withSubject(TokenConstants.SUBJECT)
            .build();

        token = encoder.encode(data);
        subject = decoder.decode(token)
            .getSubject();

        Assertions.assertThat(subject)
            .isEqualTo(TokenConstants.SUBJECT);
    }

    @Test
    @DisplayName("Recovering the subject from an expired token generates an exception")
    void testGetSubject_fromGeneratedToken_expired() throws InterruptedException {
        final String           token;
        final ThrowingCallable executable;
        final JwtTokenData     data;

        data = ImmutableJwtTokenData.builder()
            .withSubject(TokenConstants.SUBJECT)
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
