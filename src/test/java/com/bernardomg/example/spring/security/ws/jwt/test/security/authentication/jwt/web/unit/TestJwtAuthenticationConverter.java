
package com.bernardomg.example.spring.security.ws.jwt.test.security.authentication.jwt.web.unit;

import static org.mockito.BDDMockito.given;

import java.time.LocalDateTime;

import org.assertj.core.api.Assertions;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;

import com.bernardomg.example.spring.security.ws.jwt.security.authentication.jwt.token.ImmutableJwtTokenData;
import com.bernardomg.example.spring.security.ws.jwt.security.authentication.jwt.token.JjwtTokenEncoder;
import com.bernardomg.example.spring.security.ws.jwt.security.authentication.jwt.token.JwtTokenData;
import com.bernardomg.example.spring.security.ws.jwt.security.authentication.jwt.token.TokenEncoder;
import com.bernardomg.example.spring.security.ws.jwt.security.authentication.jwt.web.JwtAuthenticationConverter;
import com.bernardomg.example.spring.security.ws.jwt.test.security.authentication.jwt.token.config.TokenConstants;

import jakarta.servlet.http.HttpServletRequest;

@ExtendWith(MockitoExtension.class)
@DisplayName("JwtAuthenticationConverter")
class TestJwtAuthenticationConverter {

    private JwtAuthenticationConverter converter;

    private final TokenEncoder         encoder = new JjwtTokenEncoder(TokenConstants.KEY);

    @Mock
    private HttpServletRequest         request;

    @BeforeEach
    public void initializeConverter() {
        converter = new JwtAuthenticationConverter(TokenConstants.KEY);
    }

    private final String generateExpiredToken() {
        final JwtTokenData data;

        data = ImmutableJwtTokenData.builder()
            .withSubject(TokenConstants.SUBJECT)
            .withExpiration(LocalDateTime.now()
                .minusDays(1))
            .build();

        return encoder.encode(data);
    }

    private final String generateToken() {
        final JwtTokenData data;

        data = ImmutableJwtTokenData.builder()
            .withSubject(TokenConstants.SUBJECT)
            .build();

        return encoder.encode(data);
    }

    @Test
    @DisplayName("With an expired token no authentication is generated")
    void testConvert_Expired() {
        final Authentication auth;

        request = Mockito.mock(HttpServletRequest.class);
        given(request.getHeader(HttpHeaders.AUTHORIZATION)).willReturn("Bearer " + generateExpiredToken());

        auth = converter.convert(request);

        Assertions.assertThat(auth)
            .isNull();
    }

    @Test
    @DisplayName("With another authorization scheme no authentication is generated")
    void testConvert_IncorrectScheme() {
        final ThrowingCallable execution;

        request = Mockito.mock(HttpServletRequest.class);
        given(request.getHeader(HttpHeaders.AUTHORIZATION)).willReturn("abc");

        execution = () -> converter.convert(request);

        Assertions.assertThatThrownBy(execution)
            .isInstanceOf(BadCredentialsException.class);
    }

    @Test
    @DisplayName("With no header no authentication is generated")
    void testConvert_NoHeader() {
        final Authentication auth;

        request = Mockito.mock(HttpServletRequest.class);
        auth = converter.convert(request);

        Assertions.assertThat(auth)
            .isNull();
    }

    @Test
    @DisplayName("With bearer missing a token no authentication is generated")
    void testConvert_NoToken() {
        final ThrowingCallable execution;

        request = Mockito.mock(HttpServletRequest.class);
        given(request.getHeader(HttpHeaders.AUTHORIZATION)).willReturn("Bearer");

        execution = () -> converter.convert(request);

        Assertions.assertThatThrownBy(execution)
            .isInstanceOf(BadCredentialsException.class);
    }

    @Test
    @DisplayName("With a valid token an authentication object is generated")
    void testConvert_Valid() {
        final Authentication auth;

        request = Mockito.mock(HttpServletRequest.class);
        given(request.getHeader(HttpHeaders.AUTHORIZATION)).willReturn("Bearer " + generateToken());

        auth = converter.convert(request);

        Assertions.assertThat(auth.getName())
            .isEqualTo(TokenConstants.SUBJECT);
    }

}
