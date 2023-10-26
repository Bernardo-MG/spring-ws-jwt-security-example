
package com.bernardomg.example.spring.security.ws.jwt.test.security.authentication.jwt.web.unit;

import static org.mockito.BDDMockito.given;

import java.time.LocalDateTime;
import java.util.List;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

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

    @Mock
    private UserDetailsService         userDetService;

    @BeforeEach
    public void initializeConverter() {
        converter = new JwtAuthenticationConverter(userDetService, TokenConstants.KEY);
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
        final Authentication auth;

        request = Mockito.mock(HttpServletRequest.class);
        given(request.getHeader(HttpHeaders.AUTHORIZATION)).willReturn("abc");

        auth = converter.convert(request);

        Assertions.assertThat(auth)
            .isNull();
    }

    @Test
    @DisplayName("With no username for the token no authentication is generated")
    void testConvert_InvalidToken() {
        final Authentication auth;

        request = Mockito.mock(HttpServletRequest.class);
        given(request.getHeader(HttpHeaders.AUTHORIZATION)).willReturn("Bearer " + generateToken());

        given(userDetService.loadUserByUsername(TokenConstants.SUBJECT)).willThrow(UsernameNotFoundException.class);

        auth = converter.convert(request);

        Assertions.assertThat(auth)
            .isNull();
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
    @DisplayName("With a valid token and user an authentication object is generated")
    void testConvert_Valid() {
        final Authentication auth;
        final UserDetails    userDetails;

        request = Mockito.mock(HttpServletRequest.class);
        given(request.getHeader(HttpHeaders.AUTHORIZATION)).willReturn("Bearer " + generateToken());

        userDetails = User.builder()
            .username(TokenConstants.SUBJECT)
            .password("")
            .authorities(List.of())
            .build();
        given(userDetService.loadUserByUsername(TokenConstants.SUBJECT)).willReturn(userDetails);

        auth = converter.convert(request);

        Assertions.assertThat(auth.getName())
            .isEqualTo(TokenConstants.SUBJECT);
    }

}
