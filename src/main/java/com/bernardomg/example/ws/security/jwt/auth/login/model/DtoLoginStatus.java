
package com.bernardomg.example.ws.security.jwt.auth.login.model;

import lombok.Data;

@Data
public final class DtoLoginStatus implements LoginStatus {

    private Boolean logged;

    private String  token;

}
