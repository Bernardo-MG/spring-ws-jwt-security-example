
package com.bernardomg.example.spring.security.ws.jwt.test.encoding.jjwt.unit;

import java.time.LocalDateTime;

import org.assertj.core.api.Assertions;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.bernardomg.example.spring.security.ws.jwt.encoding.JwtTokenData;
import com.bernardomg.example.spring.security.ws.jwt.encoding.TokenDecoder;
import com.bernardomg.example.spring.security.ws.jwt.encoding.TokenEncoder;
import com.bernardomg.example.spring.security.ws.jwt.encoding.jjwt.JjwtTokenDecoder;
import com.bernardomg.example.spring.security.ws.jwt.encoding.jjwt.JjwtTokenEncoder;
import com.bernardomg.example.spring.security.ws.jwt.test.encoding.jjwt.config.TokenConstants;

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

        data = JwtTokenData.builder()
            .withSubject(TokenConstants.SUBJECT)
            .build();

        token = encoder.encode(data);
        subject = decoder.decode(token)
            .subject();

        Assertions.assertThat(subject)
            .isEqualTo(TokenConstants.SUBJECT);
    }

    @Test
    @DisplayName("Recovering the subject from an expired token generates an exception")
    void testGetSubject_fromGeneratedToken_expired() throws InterruptedException {
        final String           token;
        final ThrowingCallable executable;
        final JwtTokenData     data;

        data = JwtTokenData.builder()
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
