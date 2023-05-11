
package com.bernardomg.example.spring.security.ws.jwt.security.jwt.token;

import java.util.Date;

public interface JwtTokenData {

    public Date getExpiration();

    public Date getIssuedAt();

    public String getSubject();

    public Date getValidity();

}
