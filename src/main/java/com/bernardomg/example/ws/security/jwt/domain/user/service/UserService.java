
package com.bernardomg.example.ws.security.jwt.domain.user.service;

import com.bernardomg.example.ws.security.jwt.domain.user.model.User;

public interface UserService {

    public Iterable<? extends User> getUsers();

}
