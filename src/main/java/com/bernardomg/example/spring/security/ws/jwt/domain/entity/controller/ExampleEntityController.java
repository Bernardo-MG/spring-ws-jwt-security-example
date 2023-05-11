/**
 * The MIT License (MIT)
 * <p>
 * Copyright (c) 2022-2023 the original author or authors.
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

package com.bernardomg.example.spring.security.ws.jwt.domain.entity.controller;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.bernardomg.example.spring.security.ws.jwt.domain.entity.model.ExampleEntity;
import com.bernardomg.example.spring.security.ws.jwt.domain.entity.service.ExampleEntityService;

import lombok.AllArgsConstructor;

/**
 * Rest controller for the example entities.
 *
 * @author Bernardo Mart&iacute;nez Garrido
 */
@RestController
@RequestMapping("/rest/entity")
@AllArgsConstructor
public class ExampleEntityController {

    /**
     * Example entity service.
     */
    private final ExampleEntityService exampleEntityService;

    /**
     * Creates an entity.
     *
     * @param entity
     *            entity to create
     * @return the created entity
     */
    @PostMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    public ExampleEntity create(final ExampleEntity entity) {
        return exampleEntityService.create(entity);
    }

    /**
     * Deletes the entity for the received id.
     *
     * @param id
     *            id of the entity to delete
     * @return {@code true} if it was deleted, {@code false} otherwise
     */
    @DeleteMapping(path = "/{id}", produces = MediaType.APPLICATION_JSON_VALUE)
    public Boolean delete(@PathVariable("id") final Long id) {
        return exampleEntityService.delete(id);
    }

    /**
     * Returns all the entities.
     *
     * @return all the entities
     */
    @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    public Iterable<ExampleEntity> read() {
        return exampleEntityService.getAll();
    }

    /**
     * Updates the entity for the received id.
     *
     * @param id
     *            entity id
     * @param entity
     *            new entity data
     * @return the updated entity
     */
    @PutMapping(path = "/{id}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ExampleEntity update(@PathVariable("id") final Long id, @RequestBody final ExampleEntity entity) {
        return exampleEntityService.update(id, entity);
    }

}
