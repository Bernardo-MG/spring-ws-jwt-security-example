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

package com.bernardomg.example.spring.security.ws.jwt.domain.entity.service;

import org.springframework.security.access.prepost.PreAuthorize;

import com.bernardomg.example.spring.security.ws.jwt.domain.entity.model.ExampleEntity;

/**
 * Service for the example entity domain.
 * <p>
 * This is a domain service just to allow the endpoints querying the entities they are asked for.
 *
 * @author Bernardo Mart&iacute;nez Garrido
 */
public interface ExampleEntityService {

    /**
     * Creates the received entity.
     *
     * @param entity
     *            entity to create
     * @return the entity created
     */
    @PreAuthorize("hasAuthority('CREATE_DATA')")
    public ExampleEntity create(final ExampleEntity entity);

    /**
     * Deletes the entity for the received id.
     *
     * @param id
     *            entity id
     * @return {@code true} if it was deleted, {@code false} otherwise
     */
    @PreAuthorize("hasAuthority('DELETE_DATA')")
    public Boolean delete(final Long id);

    /**
     * Returns all the entities.
     *
     * @return all the entities
     */
    @PreAuthorize("hasAuthority('READ_DATA')")
    public Iterable<? extends ExampleEntity> getAll();

    /**
     * Updates the entity for the received id.
     *
     * @param id
     *            entity id
     * @param entity
     *            new entity data
     * @return the updated entity
     */
    @PreAuthorize("hasAuthority('UPDATE_DATA')")
    public ExampleEntity update(final Long id, final ExampleEntity entity);

}
