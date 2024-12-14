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

package com.bernardomg.example.spring.security.ws.jwt.springframework.userdetails;

import java.util.Collection;
import java.util.Locale;
import java.util.Objects;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.bernardomg.example.spring.security.ws.jwt.user.domain.model.Privilege;
import com.bernardomg.example.spring.security.ws.jwt.user.domain.model.User;
import com.bernardomg.example.spring.security.ws.jwt.user.domain.repository.UserRepository;

import lombok.extern.slf4j.Slf4j;

/**
 * User details service which takes the user data from the persistence layer.
 * <p>
 * Makes use of repositories, which will return the user and his privileges.
 * <p>
 * The user search is based on the username, and is case insensitive. As the persisted user details are expected to
 * contain the username in lower case.
 * <h2>Granted authorities</h2>
 * <p>
 * Privileges are read moving through the model. The service receives a username and then finds the privileges assigned
 * to the related user:
 * <p>
 * {@code user -> role -> privileges}
 * <p>
 * These privileges are used to create the granted authorities.
 * <h2>Exceptions</h2>
 * <p>
 * When loading users any of these cases throws a {@code UsernameNotFoundException}:
 * <ul>
 * <li>There is no user for the username</li>
 * <li>Theres is a user, but he has no privileges</li>
 * </ul>
 *
 * @author Bernardo Mart&iacute;nez Garrido
 *
 */
@Slf4j
public final class UserDomainDetailsService implements UserDetailsService {

    /**
     * User repository.
     */
    private final UserRepository userRepository;

    /**
     * Constructs a user details service.
     *
     * @param userRepo
     *            users repository
     */
    public UserDomainDetailsService(final UserRepository userRepo) {
        super();

        userRepository = Objects.requireNonNull(userRepo, "Received a null pointer as user repository");
    }

    @Override
    public final UserDetails loadUserByUsername(final String username) throws UsernameNotFoundException {
        final User        user;
        final UserDetails details;
        final String      password;

        user = userRepository.findOne(username.toLowerCase(Locale.getDefault()))
            .orElseThrow(() -> {
                log.error("Username {} not found in database", username);
                throw new UsernameNotFoundException(String.format("Username %s not found in database", username));
            });

        if (user.privileges()
            .isEmpty()) {
            log.error("Username {} has no authorities", username);
            throw new UsernameNotFoundException(String.format("Username %s has no authorities", username));
        }

        password = userRepository.findPassword(username)
            .get();
        details = toUserDetails(user, password);

        log.debug("User {} exists. Enabled: {}. Non expired: {}. Non locked: {}. Credentials non expired: {}", username,
            details.isEnabled(), details.isAccountNonExpired(), details.isAccountNonLocked(),
            details.isCredentialsNonExpired());
        log.debug("Authorities for {}: {}", username, details.getAuthorities());

        return details;
    }

    /**
     * Creates a {@link GrantedAuthority} from the {@link Privilege}.
     *
     * @param privilege
     *            privilege to transform
     * @return {@code GrantedAuthority} from the {@code Privilege}
     */
    private final GrantedAuthority toGrantedAuthority(final Privilege privilege) {
        return new SimpleGrantedAuthority(privilege.name());
    }

    /**
     * Transforms a user into a user details object.
     *
     * @param user
     *            user to transform
     * @param password
     *            user password
     * @return equivalent user details
     */
    private final UserDetails toUserDetails(final User user, final String password) {
        final Boolean                                enabled;
        final Boolean                                accountNonExpired;
        final Boolean                                credentialsNonExpired;
        final Boolean                                accountNonLocked;
        final Collection<? extends GrantedAuthority> authorities;

        // Loads status
        enabled = user.enabled();
        accountNonExpired = !user.expired();
        credentialsNonExpired = !user.passwordExpired();
        accountNonLocked = !user.locked();

        // Authorities
        authorities = user.privileges()
            .stream()
            .map(this::toGrantedAuthority)
            .toList();

        return new org.springframework.security.core.userdetails.User(user.username(), password, enabled,
            accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);
    }

}
