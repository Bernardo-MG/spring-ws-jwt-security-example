
package com.bernardomg.example.ws.security.basic.resource.user.service;

import com.bernardomg.example.ws.security.basic.resource.user.model.User;

public interface UserService {

    public Iterable<? extends User> getUsers();

}
