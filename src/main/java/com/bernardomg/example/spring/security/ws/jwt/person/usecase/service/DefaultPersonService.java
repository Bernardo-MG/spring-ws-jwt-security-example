
package com.bernardomg.example.spring.security.ws.jwt.person.usecase.service;

import java.util.Collection;
import java.util.Objects;

import org.springframework.stereotype.Service;

import com.bernardomg.example.spring.security.ws.jwt.person.domain.model.Person;
import com.bernardomg.example.spring.security.ws.jwt.person.domain.repository.PersonRepository;

import lombok.extern.slf4j.Slf4j;

/**
 * Default person service, which just takes the data from the person repository.
 */
@Slf4j
@Service
public final class DefaultPersonService implements PersonService {

    /**
     * Person repository to read the data.
     */
    private final PersonRepository personRepository;

    public DefaultPersonService(final PersonRepository personRepo) {
        super();

        personRepository = Objects.requireNonNull(personRepo);
    }

    @Override
    public final Collection<Person> getAll() {
        log.debug("Reading all persons");

        return personRepository.findAll();
    }

}
