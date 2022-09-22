
package com.bernardomg.example.ws.security.jwt.domain.user.service;

import org.springframework.stereotype.Service;

import com.bernardomg.example.ws.security.jwt.domain.user.model.User;
import com.bernardomg.example.ws.security.jwt.domain.user.repository.PersistentUserRepository;

import lombok.AllArgsConstructor;

@Service
@AllArgsConstructor
public final class DefaultUserService implements UserService {

    private final PersistentUserRepository repository;

    @Override
    public final Iterable<? extends User> getUsers() {
        return repository.findAll();
    }

}
