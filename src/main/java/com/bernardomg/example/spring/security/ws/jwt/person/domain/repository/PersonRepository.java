
package com.bernardomg.example.spring.security.ws.jwt.person.domain.repository;

import java.util.Collection;

import com.bernardomg.example.spring.security.ws.jwt.person.domain.model.Person;

/**
 * Person repository.
 */
public interface PersonRepository {

    public Collection<Person> findAll();

}
