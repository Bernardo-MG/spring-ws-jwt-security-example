
package com.bernardomg.example.spring.security.ws.jwt.person.usecase.service;

import java.util.Collection;

import com.bernardomg.example.spring.security.ws.jwt.person.domain.model.Person;

/**
 * Person service.
 */
public interface PersonService {

    /**
     * Returns all the people.
     * 
     * @return all the people
     */
    public Collection<Person> getAll();

}
