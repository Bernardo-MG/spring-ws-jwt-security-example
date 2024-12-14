/**
 * The MIT License (MIT)
 * <p>
 * Copyright (c) 2023 the original author or authors.
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

package com.bernardomg.example.spring.security.ws.jwt.person.adapter.inbound.user.repository;

import java.util.Collection;
import java.util.Objects;

import org.springframework.stereotype.Repository;

import com.bernardomg.example.spring.security.ws.jwt.person.domain.model.Person;
import com.bernardomg.example.spring.security.ws.jwt.person.domain.repository.PersonRepository;
import com.bernardomg.example.spring.security.ws.jwt.user.domain.model.User;
import com.bernardomg.example.spring.security.ws.jwt.user.domain.repository.UserRepository;

import lombok.extern.slf4j.Slf4j;

/**
 * Person repository which takes the data from the users. Reads from the users repository, and maps into {@code Person}.
 */
@Slf4j
@Repository
public final class UserPersonRepository implements PersonRepository {

    /**
     * User repository. The data for the persons is taken from here.
     */
    private final UserRepository userRepository;

    public UserPersonRepository(final UserRepository userRepo) {
        super();

        userRepository = Objects.requireNonNull(userRepo, "Received a null pointer as user repository");
    }

    @Override
    public final Collection<Person> findAll() {
        final Collection<Person> persons;

        log.debug("Finding all the persons");

        persons = userRepository.findAll()
            .stream()
            .map(this::toPerson)
            .toList();

        log.debug("Found all the persons: {}", persons);

        return persons;
    }

    private final Person toPerson(final User user) {
        return new Person(user.username(), user.name());
    }

}
