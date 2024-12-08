
package com.bernardomg.example.spring.security.ws.jwt.person.adapter.inbound.placeholder.repository;

import java.util.Collection;
import java.util.List;

import org.springframework.stereotype.Repository;

import com.bernardomg.example.spring.security.ws.jwt.person.domain.model.Person;
import com.bernardomg.example.spring.security.ws.jwt.person.domain.repository.PersonRepository;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Repository
public final class PlaceholderPersonRepository implements PersonRepository {

    public PlaceholderPersonRepository() {
        super();
    }

    @Override
    public final Collection<Person> findAll() {
        final Person             person;
        final Collection<Person> persons;

        log.debug("Finding all the persons");

        person = new Person("id", "Name", "Surname");

        persons = List.of(person);

        log.debug("Found all the persons: {}", persons);

        return persons;
    }

}
