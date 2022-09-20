
package com.bernardomg.example.ws.security.basic.resource.model.user.service;

import com.bernardomg.example.ws.security.basic.resource.model.user.model.User;

public interface UserService {

    public Iterable<? extends User> getUsers();

}
