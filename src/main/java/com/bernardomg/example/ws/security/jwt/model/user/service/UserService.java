
package com.bernardomg.example.ws.security.jwt.model.user.service;

import com.bernardomg.example.ws.security.jwt.model.user.model.User;

public interface UserService {

    public Iterable<? extends User> getUsers();

}
