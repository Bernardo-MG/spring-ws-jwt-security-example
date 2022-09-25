/**
 * The MIT License (MIT)
 * <p>
 * Copyright (c) 2022 the original author or authors.
 * <p>
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * <p>
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * <p>
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package com.bernardomg.example.ws.security.jwt.domain.user.service;

import java.util.stream.Collectors;

import org.springframework.stereotype.Service;

import com.bernardomg.example.ws.security.jwt.domain.user.model.DtoPrivilege;
import com.bernardomg.example.ws.security.jwt.domain.user.model.DtoRole;
import com.bernardomg.example.ws.security.jwt.domain.user.model.DtoUser;
import com.bernardomg.example.ws.security.jwt.domain.user.model.Privilege;
import com.bernardomg.example.ws.security.jwt.domain.user.model.Role;
import com.bernardomg.example.ws.security.jwt.domain.user.model.User;
import com.bernardomg.example.ws.security.jwt.domain.user.model.persistence.PersistentPrivilege;
import com.bernardomg.example.ws.security.jwt.domain.user.model.persistence.PersistentRole;
import com.bernardomg.example.ws.security.jwt.domain.user.model.persistence.PersistentUser;
import com.bernardomg.example.ws.security.jwt.domain.user.repository.PersistentUserRepository;

import lombok.AllArgsConstructor;

@Service
@AllArgsConstructor
public final class DefaultUserService implements UserService {

    /**
     * User repository.
     */
    private final PersistentUserRepository repository;

    @Override
    public final Iterable<? extends User> getUsers() {
        return repository.findAll()
            .stream()
            .map(this::toDto)
            .collect(Collectors.toList());
    }

    private final Privilege toDto(final PersistentPrivilege entity) {
        final DtoPrivilege dto;

        dto = new DtoPrivilege();
        dto.setId(entity.getId());
        dto.setName(entity.getName());

        return dto;
    }

    private final Role toDto(final PersistentRole entity) {
        final DtoRole dto;

        dto = new DtoRole();
        dto.setId(entity.getId());
        dto.setName(entity.getName());

        dto.setPrivileges(entity.getPrivileges()
            .stream()
            .map(this::toDto)
            .collect(Collectors.toList()));

        return dto;
    }

    private final User toDto(final PersistentUser entity) {
        final DtoUser dto;

        dto = new DtoUser();
        dto.setId(entity.getId());
        dto.setUsername(entity.getUsername());
        // TODO: Filter out password
        // dto.setPassword(null);
        dto.setCredentialsExpired(entity.getCredentialsExpired());
        dto.setEmail(entity.getEmail());
        dto.setEnabled(entity.getEnabled());
        dto.setExpired(entity.getExpired());
        dto.setLocked(entity.getLocked());

        dto.setRoles(entity.getRoles()
            .stream()
            .map(this::toDto)
            .collect(Collectors.toList()));

        return dto;
    }

}
