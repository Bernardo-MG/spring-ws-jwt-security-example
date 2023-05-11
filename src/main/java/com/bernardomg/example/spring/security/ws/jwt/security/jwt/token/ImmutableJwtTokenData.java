
package com.bernardomg.example.spring.security.ws.jwt.security.jwt.token;

import java.util.Date;

import lombok.Builder;
import lombok.Value;

@Value
@Builder(setterPrefix = "with")
public class ImmutableJwtTokenData implements JwtTokenData {

    private final Date   expiration;

    private final Date   issuedAt;

    private final String subject;

    private final Date   validity;

}
