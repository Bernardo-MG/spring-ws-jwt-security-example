
package com.bernardomg.example.spring.security.ws.jwt.test.web.authentication.unit;

import static org.mockito.BDDMockito.given;

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

import com.bernardomg.example.spring.security.ws.jwt.security.jwt.token.ImmutableJwtTokenData;
import com.bernardomg.example.spring.security.ws.jwt.security.jwt.token.JjwtTokenEncoder;
import com.bernardomg.example.spring.security.ws.jwt.security.jwt.token.JwtTokenData;
import com.bernardomg.example.spring.security.ws.jwt.security.jwt.token.TokenEncoder;
import com.bernardomg.example.spring.security.ws.jwt.security.jwt.web.authentication.JwtAuthenticationConverter;
import com.bernardomg.example.spring.security.ws.jwt.test.security.jwt.token.config.TokenConstants;

import jakarta.servlet.http.HttpServletRequest;

@ExtendWith(MockitoExtension.class)
@DisplayName("JwtAuthenticationConverter - User status")
class TestJwtAuthenticationConverterUserStatus {

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

    private final String generateToken() {
        final JwtTokenData data;

        data = ImmutableJwtTokenData.builder()
            .withSubject(TokenConstants.SUBJECT)
            .build();

        return encoder.encode(data);
    }

    @Test
    @DisplayName("With a user having expired credentials no authentication is generated")
    void testConvert_CredentialsExpired() {
        final Authentication auth;
        final UserDetails    userDetails;

        request = Mockito.mock(HttpServletRequest.class);
        given(request.getHeader(HttpHeaders.AUTHORIZATION)).willReturn("Bearer " + generateToken());

        userDetails = User.builder()
            .username(TokenConstants.SUBJECT)
            .password("")
            .authorities(List.of())
            .credentialsExpired(true)
            .build();
        given(userDetService.loadUserByUsername(TokenConstants.SUBJECT)).willReturn(userDetails);

        auth = converter.convert(request);

        Assertions.assertThat(auth)
            .isNull();
    }

    @Test
    @DisplayName("With a disabled user no authentication is generated")
    void testConvert_Disabled() {
        final Authentication auth;
        final UserDetails    userDetails;

        request = Mockito.mock(HttpServletRequest.class);
        given(request.getHeader(HttpHeaders.AUTHORIZATION)).willReturn("Bearer " + generateToken());

        userDetails = User.builder()
            .username(TokenConstants.SUBJECT)
            .password("")
            .authorities(List.of())
            .disabled(true)
            .build();
        given(userDetService.loadUserByUsername(TokenConstants.SUBJECT)).willReturn(userDetails);

        auth = converter.convert(request);

        Assertions.assertThat(auth)
            .isNull();
    }

    @Test
    @DisplayName("With an expired user no authentication is generated")
    void testConvert_Expired() {
        final Authentication auth;
        final UserDetails    userDetails;

        request = Mockito.mock(HttpServletRequest.class);
        given(request.getHeader(HttpHeaders.AUTHORIZATION)).willReturn("Bearer " + generateToken());

        userDetails = User.builder()
            .username(TokenConstants.SUBJECT)
            .password("")
            .authorities(List.of())
            .accountExpired(true)
            .build();
        given(userDetService.loadUserByUsername(TokenConstants.SUBJECT)).willReturn(userDetails);

        auth = converter.convert(request);

        Assertions.assertThat(auth)
            .isNull();
    }

    @Test
    @DisplayName("With a locked user no authentication is generated")
    void testConvert_Locked() {
        final Authentication auth;
        final UserDetails    userDetails;

        request = Mockito.mock(HttpServletRequest.class);
        given(request.getHeader(HttpHeaders.AUTHORIZATION)).willReturn("Bearer " + generateToken());

        userDetails = User.builder()
            .username(TokenConstants.SUBJECT)
            .password("")
            .authorities(List.of())
            .accountLocked(true)
            .build();
        given(userDetService.loadUserByUsername(TokenConstants.SUBJECT)).willReturn(userDetails);

        auth = converter.convert(request);

        Assertions.assertThat(auth)
            .isNull();
    }

}
