/**
 * The MIT License (MIT)
 * <p>
 * Copyright (c) 2017-2020 the original author or authors.
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

package com.bernardomg.example.ws.security.basic.resource.user.model.persistence;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.persistence.Table;

import com.bernardomg.example.ws.security.basic.resource.user.model.Role;

import lombok.Data;

/**
 * Persistent implementation of {@code Role}.
 * 
 * @author Bernardo Mart&iacute;nez Garrido
 *
 */
@Entity(name = "Role")
@Table(name = "ROLES")
@Data
public class PersistentRole implements Role, Serializable {

    /**
     * Serialization id.
     */
    private static final long               serialVersionUID = 8513041662486312372L;

    /**
     * Entity id.
     */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false, unique = true)
    private Long                            id;

    /**
     * Authority name.
     */
    @Column(name = "name", nullable = false, unique = true, length = 60)
    private String                          name;

    /**
     * Granted privileges.
     */
    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name = "ROLE_PRIVILEGES",
            joinColumns = @JoinColumn(name = "role_id",
                    referencedColumnName = "id"),
            inverseJoinColumns = @JoinColumn(name = "privilege_id",
                    referencedColumnName = "id"))
    private Collection<PersistentPrivilege> privileges       = new ArrayList<>();

    /**
     * Default constructor.
     */
    public PersistentRole() {
        super();
    }

}
