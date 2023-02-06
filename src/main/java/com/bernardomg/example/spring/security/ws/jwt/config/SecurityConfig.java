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

package com.bernardomg.example.spring.security.ws.jwt.config;

import java.nio.charset.Charset;

import javax.crypto.SecretKey;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.bernardomg.example.spring.security.ws.jwt.security.jwt.token.JwtTokenProvider;
import com.bernardomg.example.spring.security.ws.jwt.security.jwt.token.JwtTokenValidator;
import com.bernardomg.example.spring.security.ws.jwt.security.property.JwtProperties;
import com.bernardomg.example.spring.security.ws.jwt.security.token.provider.TokenProvider;
import com.bernardomg.example.spring.security.ws.jwt.security.user.persistence.repository.PrivilegeRepository;
import com.bernardomg.example.spring.security.ws.jwt.security.user.persistence.repository.UserRepository;
import com.bernardomg.example.spring.security.ws.jwt.security.userdetails.PersistentUserDetailsService;

import io.jsonwebtoken.security.Keys;

/**
 * Security configuration.
 *
 * @author Bernardo Mart&iacute;nez Garrido
 *
 */
@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
public class SecurityConfig {

    /**
     * Default constructor.
     */
    public SecurityConfig() {
        super();
    }

    /**
     * Returns the JWT secret key for hashing.
     *
     * @param properties
     *            JWT configuration properties
     * @return the JWT secret key for hashing
     */
    @Bean("jwtSecretKey")
    public SecretKey getJwtSecretKey(final JwtProperties properties) {
        return Keys.hmacShaKeyFor(properties.getSecret()
            .getBytes(Charset.forName("UTF-8")));
    }

    /**
     * Password encoder. Used to match the received password to the one securely stored in the DB.
     *
     * @return the password encoder
     */
    @Bean("passwordEncoder")
    public PasswordEncoder getPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Returns the token provider.
     *
     * @param key
     *            secret key for hashing
     * @param properties
     *            JWT configuration properties
     * @return the token provider
     */
    @Bean("tokenProvider")
    public TokenProvider getTokenProvider(final SecretKey key, final JwtProperties properties) {
        return new JwtTokenProvider(key, properties.getValidity());
    }

    /**
     * Returns the token validator.
     *
     * @param key
     *            secret key for hashing
     * @return the token validator
     */
    @Bean("tokenValidator")
    public JwtTokenValidator getTokenValidator(final SecretKey key) {
        return new JwtTokenValidator(key);
    }

    /**
     * User details service. Will take care of finding registered users.
     *
     * @param userRepository
     *            repository for finding users
     * @param privilegeRepository
     *            repository for finding user privileges
     * @return the user details service
     */
    @Bean("userDetailsService")
    public UserDetailsService getUserDetailsService(final UserRepository userRepository,
            final PrivilegeRepository privilegeRepository) {
        return new PersistentUserDetailsService(userRepository, privilegeRepository);
    }

}
