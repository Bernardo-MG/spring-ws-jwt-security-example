
package com.bernardomg.example.spring.security.ws.jwt.test.encoding.jjwt.unit;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.bernardomg.example.spring.security.ws.jwt.encoding.JwtTokenData;
import com.bernardomg.example.spring.security.ws.jwt.encoding.TokenEncoder;
import com.bernardomg.example.spring.security.ws.jwt.encoding.jjwt.JjwtTokenEncoder;
import com.bernardomg.example.spring.security.ws.jwt.test.encoding.jjwt.config.TokenConstants;

@DisplayName("JjwtTokenEncoder - generate token")
class TestJjwtTokenEncoderGenerateToken {

    private final TokenEncoder encoder = new JjwtTokenEncoder(TokenConstants.KEY);

    @Test
    @DisplayName("Encodes a token")
    void testGenerateToken() {
        final String       token;
        final JwtTokenData data;

        data = JwtTokenData.builder()
            .build();

        token = encoder.encode(data);

        Assertions.assertThat(token)
            .isNotEmpty();
    }

}
