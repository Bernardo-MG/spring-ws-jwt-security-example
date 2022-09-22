
package com.bernardomg.example.ws.security.jwt.auth.processor;

import java.nio.charset.Charset;
import java.util.Date;
import java.util.Objects;
import java.util.function.Function;

import javax.crypto.SecretKey;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;

/**
 * JWT token processor.
 *
 * @author Bernardo Mart&iacute;nez Garrido
 *
 */
@Slf4j
public final class JwtTokenProcessor implements TokenProcessor {

    private final SecretKey key;

    private final Integer   validity;

    public JwtTokenProcessor(final String secret, final Integer vldt) {
        super();

        key = Keys.hmacShaKeyFor(secret.getBytes(Charset.forName("UTF-8")));
        validity = Objects.requireNonNull(vldt);
    }

    @Override
    public final String generateToken(final String subject) {
        return Jwts.builder()
            .setSubject(subject)
            .setIssuedAt(new Date(System.currentTimeMillis()))
            .setExpiration(new Date(System.currentTimeMillis() + (validity * 1000)))
            .signWith(key, SignatureAlgorithm.HS512)
            .compact();
    }

    @Override
    public final String getSubject(final String token) {
        return getClaim(token, Claims::getSubject);
    }

    @Override
    public final Boolean validate(final String token, final String subject) {
        final String  subj;
        final Boolean valid;

        subj = getSubject(token);

        if (!subj.equals(subject)) {
            log.debug("Received subject {} does not match subject {} from token", subject, subj, token);
            valid = false;
        } else if (isExpired(token)) {
            log.debug("Expired token", token);
            valid = false;
        } else {
            valid = true;
        }

        return valid;
    }

    /**
     * Returns all claims from the token.
     *
     * @param token
     *            token to parse
     * @return all the claims from the token
     */
    private final Claims getAllClaims(final String token) {
        return Jwts.parserBuilder()
            .setSigningKey(key)
            .build()
            .parseClaimsJws(token)
            .getBody();
    }

    /**
     * Returns a claim from the token, defined through the claim resolver.
     *
     * @param <T>
     *            type of the claim
     * @param token
     *            token to parse
     * @param resolver
     *            claim resolver
     * @return the claim from the token and resolver
     */
    private final <T> T getClaim(final String token, final Function<Claims, T> resolver) {
        final Claims claims;

        claims = getAllClaims(token);
        return resolver.apply(claims);
    }

    /**
     * Returns if the token is expired.
     *
     * @param token
     *            token to parse
     * @return {@code true} if the token is expired, {@code false} otherwise
     */
    private final Boolean isExpired(final String token) {
        final Date expiration;

        expiration = getClaim(token, Claims::getExpiration);
        return expiration.before(new Date());
    }

}
