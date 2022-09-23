
package com.bernardomg.example.ws.security.jwt.auth.jwt.processor;

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
        final Date expiration;
        final Date issuedAt;

        issuedAt = new Date();
        expiration = new Date(System.currentTimeMillis() + (validity * 1000));

        log.debug("Setting expiration date {}", expiration);

        return Jwts.builder()
            .setSubject(subject)
            .setIssuedAt(issuedAt)
            .setExpiration(expiration)
            .signWith(key, SignatureAlgorithm.HS512)
            .compact();
    }

    @Override
    public final String getSubject(final String token) {
        final String subject;

        subject = getClaim(token, Claims::getSubject);

        log.debug("Found subject {}", subject);

        return subject;
    }

    @Override
    public final Boolean validate(final String token, final String subject) {
        final String  subj;
        final Boolean valid;

        subj = getSubject(token);

        if (!subj.equals(subject)) {
            log.debug("Received subject {} does not match subject {} from token", subject, subj);
            valid = false;
        } else if (isExpired(token)) {
            log.debug("Expired token");
            valid = false;
        } else {
            log.debug("Valid token");
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
        final Date    expiration;
        final Date    current;
        final Boolean expired;

        expiration = getClaim(token, Claims::getExpiration);

        current = new Date();
        expired = expiration.before(current);

        log.debug("Token expires on {}, and the current date is {}. Expired? {}", expiration, current, expired);

        return expired;
    }

}
