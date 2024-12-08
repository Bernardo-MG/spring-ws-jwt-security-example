
package com.bernardomg.example.spring.security.ws.jwt.person.usecase.service;

import java.util.Collection;

import com.bernardomg.example.spring.security.ws.jwt.person.domain.model.Person;

public interface PersonService {

    public Collection<Person> getAll();

}
