
package com.bernardomg.example.ws.security.jwt.auth.jwt.processor;

/**
 * Token processor.
 *
 * @author Bernardo Mart&iacute;nez Garrido
 *
 */
public interface TokenProcessor {

    /**
     * Generates a token for the subject.
     *
     * @param subject
     *            subject of the token
     * @return token for the subject
     */
    public String generateToken(final String subject);

    /**
     * Returns the subject from the received token.
     *
     * @param token
     *            to parse and extract the subject
     * @return subject from the token
     */
    public String getSubject(final String token);

    /**
     * Validates the token and subject.
     *
     * @param token
     *            token to validate
     * @param username
     *            subject of the token
     * @return {@code true} if the token is valid, {@code false} otherwise
     */
    public Boolean validate(final String token, final String username);

}
