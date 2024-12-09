
package com.bernardomg.example.spring.security.ws.jwt.login.usecase.encoder;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Objects;

import com.bernardomg.example.spring.security.ws.jwt.encoding.JwtTokenData;
import com.bernardomg.example.spring.security.ws.jwt.encoding.TokenEncoder;

import lombok.extern.slf4j.Slf4j;

/**
 * Encodes a JWT token including the permissions for the user.
 *
 * @author Bernardo Mart&iacute;nez Garrido
 *
 */
@Slf4j
public class JwtLoginTokenEncoder implements LoginTokenEncoder {

    /**
     * Token encoder for creating authentication tokens.
     */
    private final TokenEncoder tokenEncoder;

    /**
     * Token validity time in seconds.
     */
    private final Duration     validity;

    public JwtLoginTokenEncoder(final TokenEncoder tknEncoder, final Duration vldt) {
        super();

        tokenEncoder = Objects.requireNonNull(tknEncoder);
        validity = Objects.requireNonNull(vldt);
    }

    @Override
    public final String encode(final String username) {
        final LocalDateTime expiration;
        final LocalDateTime issuedAt;
        final String        token;
        final JwtTokenData  data;

        // Issued right now
        issuedAt = LocalDateTime.now();
        // Expires in a number of seconds equal to validity
        // TODO: handle validity in the encoder
        expiration = LocalDateTime.now()
            .plus(validity);

        // Build token data for the wrapped encoder
        data = JwtTokenData.builder()
            .withSubject(username)
            .withIssuedAt(issuedAt)
            .withNotBefore(issuedAt)
            .withExpiration(expiration)
            .build();

        token = tokenEncoder.encode(data);

        log.debug("Created token for subject {} with expiration date {}", username, expiration);

        return token;
    }

}
