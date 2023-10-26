
package com.bernardomg.example.spring.security.ws.jwt.test.security.authentication.jwt.token.unit;

import java.time.LocalDateTime;
import java.util.concurrent.TimeUnit;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.bernardomg.example.spring.security.ws.jwt.security.authentication.jwt.token.ImmutableJwtTokenData;
import com.bernardomg.example.spring.security.ws.jwt.security.authentication.jwt.token.JjwtTokenDecoder;
import com.bernardomg.example.spring.security.ws.jwt.security.authentication.jwt.token.JjwtTokenEncoder;
import com.bernardomg.example.spring.security.ws.jwt.security.authentication.jwt.token.JjwtTokenValidator;
import com.bernardomg.example.spring.security.ws.jwt.security.authentication.jwt.token.JwtTokenData;
import com.bernardomg.example.spring.security.ws.jwt.security.authentication.jwt.token.TokenDecoder;
import com.bernardomg.example.spring.security.ws.jwt.security.authentication.jwt.token.TokenEncoder;
import com.bernardomg.example.spring.security.ws.jwt.test.security.authentication.jwt.token.config.TokenConstants;

@DisplayName("JjwtTokenEncoder - has expired")
class TestJjwtTokenEncoderHasExpired {

    private final TokenEncoder       encoder = new JjwtTokenEncoder(TokenConstants.KEY);

    private final JjwtTokenValidator validator;

    public TestJjwtTokenEncoderHasExpired() {
        super();

        final TokenDecoder decoder;

        decoder = new JjwtTokenDecoder(TokenConstants.KEY);
        validator = new JjwtTokenValidator(decoder);
    }

    @Test
    @DisplayName("An expired token is identified as such")
    void testHasExpired_fromGeneratedToken_expired() throws InterruptedException {
        final String       token;
        final Boolean      expired;
        final JwtTokenData data;

        data = ImmutableJwtTokenData.builder()
            .withIssuer("issuer")
            .withExpiration(LocalDateTime.now()
                .plusSeconds(-1))
            .build();

        token = encoder.encode(data);

        TimeUnit.SECONDS.sleep(Double.valueOf(6)
            .longValue());

        expired = validator.hasExpired(token);

        Assertions.assertThat(expired)
            .isTrue();
    }

    @Test
    @DisplayName("A token without expiration is not expired")
    void testHasExpired_noExpiration() {
        final String       token;
        final Boolean      expired;
        final JwtTokenData data;

        data = ImmutableJwtTokenData.builder()
            .withIssuer("issuer")
            .build();

        token = encoder.encode(data);
        expired = validator.hasExpired(token);

        Assertions.assertThat(expired)
            .isFalse();
    }

    @Test
    @DisplayName("A not expired token is not expired")
    void testHasExpired_notExpired() {
        final String       token;
        final Boolean      expired;
        final JwtTokenData data;

        data = ImmutableJwtTokenData.builder()
            .withIssuer("issuer")
            .withExpiration(LocalDateTime.now()
                .plusMonths(1))
            .build();

        token = encoder.encode(data);
        expired = validator.hasExpired(token);

        Assertions.assertThat(expired)
            .isFalse();
    }

}
