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

package com.bernardomg.example.spring.security.ws.jwt.domain.entity.service;

import java.util.stream.Collectors;

import org.springframework.stereotype.Service;

import com.bernardomg.example.spring.security.ws.jwt.domain.entity.model.DtoExampleEntity;
import com.bernardomg.example.spring.security.ws.jwt.domain.entity.model.ExampleEntity;
import com.bernardomg.example.spring.security.ws.jwt.domain.entity.model.PersistentExampleEntity;
import com.bernardomg.example.spring.security.ws.jwt.domain.entity.repository.ExampleEntityRepository;

import lombok.AllArgsConstructor;

/**
 * Default implementation of the example entity service.
 *
 * @author Bernardo Mart&iacute;nez Garrido
 */
@Service
@AllArgsConstructor
public final class DefaultExampleEntityService implements ExampleEntityService {

    /**
     * Repository for the domain entities handled by the service.
     */
    private final ExampleEntityRepository entityRepository;

    @Override
    public final ExampleEntity create(final ExampleEntity data) {
        final PersistentExampleEntity entity;
        final PersistentExampleEntity saved;

        entity = toEntity(data);

        saved = entityRepository.save(entity);

        return toDto(saved);
    }

    @Override
    public final Boolean delete(final Long id) {
        entityRepository.deleteById(id);

        return true;
    }

    @Override
    public final Iterable<ExampleEntity> getAll() {
        return entityRepository.findAll()
            .stream()
            .map(this::toDto)
            .collect(Collectors.toList());
    }

    @Override
    public final ExampleEntity update(final Long id, final ExampleEntity data) {
        final PersistentExampleEntity entity;
        final PersistentExampleEntity saved;

        entity = toEntity(data);

        saved = entityRepository.save(entity);

        return toDto(saved);
    }

    private final ExampleEntity toDto(final PersistentExampleEntity data) {
        final DtoExampleEntity dto;

        dto = new DtoExampleEntity();
        dto.setId(data.getId());
        dto.setName(data.getName());

        return dto;
    }

    private final PersistentExampleEntity toEntity(final ExampleEntity data) {
        final PersistentExampleEntity entity;

        entity = new PersistentExampleEntity();
        entity.setId(data.getId());
        entity.setName(data.getName());

        return entity;
    }

}
