
package com.bernardomg.example.spring.security.ws.jwt.security.jwt.token;

import java.util.Objects;

import javax.crypto.SecretKey;

import com.bernardomg.example.spring.security.ws.jwt.security.token.TokenDecoder;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;

/**
 * JWT data token decoder. Builds a {@code JwtTokenData} from a JWT token.
 *
 * @author Bernardo Mart&iacute;nez Garrido
 *
 */
public final class JwtTokenDataDecoder implements TokenDecoder<JwtTokenData> {

    /**
     * JWT parser for reading tokens.
     */
    private final JwtParser parser;

    /**
     * Builds a decoder with the received parser.
     *
     * @param prsr
     *            JWT parser
     */
    public JwtTokenDataDecoder(final JwtParser prsr) {
        super();

        parser = Objects.requireNonNull(prsr);
    }

    /**
     * Builds a decoder with the received key.
     *
     * @param key
     *            secret key for the token
     */
    public JwtTokenDataDecoder(final SecretKey key) {
        super();

        Objects.requireNonNull(key);

        parser = Jwts.parser()
            .verifyWith(key)
            .build();
    }

    @Override
    public final JwtTokenData decode(final String token) {
        final Claims claims;

        claims = parser.parseSignedClaims(token)
            .getPayload();

        return ImmutableJwtTokenData.builder()
            .withSubject(claims.getSubject())
            .withIssuedAt(claims.getIssuedAt())
            .withExpiration(claims.getExpiration())
            .build();
    }

}
