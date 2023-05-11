
package com.bernardomg.example.spring.security.ws.jwt.security.jwt.token;

import java.util.Objects;

import javax.crypto.SecretKey;

import com.bernardomg.example.spring.security.ws.jwt.security.token.TokenDecoder;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;

public final class JwtTokenDataDecoder implements TokenDecoder<JwtTokenData> {

    /**
     * JWT parser for reading tokens.
     */
    private final JwtParser parser;

    public JwtTokenDataDecoder(final SecretKey key) {
        super();

        Objects.requireNonNull(key);

        parser = Jwts.parserBuilder()
            .setSigningKey(key)
            .build();
    }

    @Override
    public final JwtTokenData decode(final String token) {
        final Claims claims;

        claims = parser.parseClaimsJws(token)
            .getBody();

        return ImmutableJwtTokenData.builder()
            .withSubject(claims.getSubject())
            .withIssuedAt(claims.getIssuedAt())
            .withExpiration(claims.getExpiration())
            .build();
    }

}
