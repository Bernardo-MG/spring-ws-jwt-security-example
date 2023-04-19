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

package com.bernardomg.example.spring.security.ws.jwt.security.user.persistence.model;

import java.io.Serializable;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.TableGenerator;
import lombok.Data;

/**
 * Persistent privilege data.
 * <p>
 * JPA entities shouldn't end mixed up with the domain model. For this reason this class won't extend any generic
 * interface, and instead is a JPA POJO.
 *
 * @author Bernardo Mart&iacute;nez Garrido
 *
 */
@Data
@Entity(name = "Privilege")
@Table(name = "privileges")
@TableGenerator(name = "seq_privileges_id", table = "sequences", pkColumnName = "sequence", valueColumnName = "count",
        allocationSize = 1)
public class PersistentPrivilege implements Serializable {

    /**
     * Serialization id.
     */
    private static final long serialVersionUID = 8513041662486312372L;

    /**
     * Entity id.
     */
    @Id
    @GeneratedValue(strategy = GenerationType.TABLE, generator = "seq_privileges_id")
    @Column(name = "id", nullable = false, unique = true)
    private Long              id;

    /**
     * Privilege name.
     */
    @Column(name = "name", nullable = false, unique = true, length = 60)
    private String            name;

}
