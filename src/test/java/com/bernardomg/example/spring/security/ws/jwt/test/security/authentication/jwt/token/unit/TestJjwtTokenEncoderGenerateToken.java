
package com.bernardomg.example.spring.security.ws.jwt.test.security.authentication.jwt.token.unit;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.bernardomg.example.spring.security.ws.jwt.security.authentication.jwt.token.ImmutableJwtTokenData;
import com.bernardomg.example.spring.security.ws.jwt.security.authentication.jwt.token.JjwtTokenEncoder;
import com.bernardomg.example.spring.security.ws.jwt.security.authentication.jwt.token.JwtTokenData;
import com.bernardomg.example.spring.security.ws.jwt.security.authentication.jwt.token.TokenEncoder;
import com.bernardomg.example.spring.security.ws.jwt.test.security.authentication.jwt.token.config.TokenConstants;

@DisplayName("JjwtTokenEncoder - generate token")
class TestJjwtTokenEncoderGenerateToken {

    private final TokenEncoder encoder = new JjwtTokenEncoder(TokenConstants.KEY);

    @Test
    @DisplayName("Encodes a token")
    void testGenerateToken() {
        final String       token;
        final JwtTokenData data;

        data = ImmutableJwtTokenData.builder()
            .build();

        token = encoder.encode(data);

        Assertions.assertThat(token)
            .isNotEmpty();
    }

}
