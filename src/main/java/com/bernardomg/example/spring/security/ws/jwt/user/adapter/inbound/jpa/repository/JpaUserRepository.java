/**
 * The MIT License (MIT)
 * <p>
 * Copyright (c) 2022-2025 the original author or authors.
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

package com.bernardomg.example.spring.security.ws.jwt.user.adapter.inbound.jpa.repository;

import java.util.Collection;
import java.util.Objects;
import java.util.Optional;

import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import com.bernardomg.example.spring.security.ws.jwt.user.adapter.inbound.jpa.model.PrivilegeEntity;
import com.bernardomg.example.spring.security.ws.jwt.user.adapter.inbound.jpa.model.RoleEntity;
import com.bernardomg.example.spring.security.ws.jwt.user.adapter.inbound.jpa.model.UserEntity;
import com.bernardomg.example.spring.security.ws.jwt.user.domain.model.Privilege;
import com.bernardomg.example.spring.security.ws.jwt.user.domain.model.User;
import com.bernardomg.example.spring.security.ws.jwt.user.domain.repository.UserRepository;

/**
 * JPA implementation of the user repository.
 *
 * @author Bernardo Mart&iacute;nez Garrido
 */
@Repository
@Transactional
public final class JpaUserRepository implements UserRepository {

    private final UserSpringRepository userSpringRepository;

    public JpaUserRepository(final UserSpringRepository userSpringRepo) {
        super();

        userSpringRepository = Objects.requireNonNull(userSpringRepo, "Received a null pointer as user repository");
    }

    @Override
    public final Collection<User> findAll() {
        return userSpringRepository.findAll()
            .stream()
            .map(this::toDomain)
            .toList();
    }

    @Override
    public Optional<User> findOne(final String username) {
        return userSpringRepository.findOneByUsername(username)
            .map(this::toDomain);
    }

    @Override
    public Optional<String> findPassword(final String username) {
        return userSpringRepository.findOneByUsername(username)
            .map(UserEntity::getPassword);
    }

    private Privilege toDomain(final PrivilegeEntity entity) {
        return new Privilege(entity.getName());
    }

    private User toDomain(final UserEntity entity) {
        final Collection<Privilege> privileges;

        privileges = entity.getRoles()
            .stream()
            .map(RoleEntity::getPrivileges)
            .flatMap(Collection::stream)
            .map(this::toDomain)
            .toList();
        return User.builder()
            .withName(entity.getName())
            .withEmail(entity.getEmail())
            .withUsername(entity.getUsername())
            .withEnabled(entity.getEnabled())
            .withExpired(entity.getExpired())
            .withLocked(entity.getLocked())
            .withPasswordExpired(entity.getCredentialsExpired())
            .withPrivileges(privileges)
            .build();
    }

}
