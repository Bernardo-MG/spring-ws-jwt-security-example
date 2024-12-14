/**
 * The MIT License (MIT)
 * <p>
 * Copyright (c) 2022-2025 the original author or authors.
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

package com.bernardomg.example.spring.security.ws.jwt.user.adapter.inbound.jpa.model;

import java.io.Serializable;
import java.util.Collection;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import jakarta.persistence.TableGenerator;
import lombok.Data;

/**
 * Role entity.
 *
 * @author Bernardo Mart&iacute;nez Garrido
 *
 */
@Data
@Entity(name = "Role")
@Table(name = "roles")
@TableGenerator(name = "seq_roles_id", table = "sequences", pkColumnName = "sequence", valueColumnName = "count",
        allocationSize = 1)
public class RoleEntity implements Serializable {

    /**
     * Serialization id.
     */
    private static final long           serialVersionUID = 8513041662486312372L;

    /**
     * Entity id.
     */
    @Id
    @GeneratedValue(strategy = GenerationType.TABLE, generator = "seq_privileges_id")
    @Column(name = "id", nullable = false, unique = true)
    private Long                        id;

    /**
     * Privilege name.
     */
    @Column(name = "name", nullable = false, unique = true, length = 60)
    private String                      name;

    @OneToMany
    @JoinTable(name = "role_privileges", joinColumns = { @JoinColumn(name = "role_id", referencedColumnName = "id") },
            inverseJoinColumns = { @JoinColumn(name = "privilege_id", referencedColumnName = "id") })
    private Collection<PrivilegeEntity> privileges;

}
