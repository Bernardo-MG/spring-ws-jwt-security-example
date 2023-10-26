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

import java.nio.charset.StandardCharsets;
import java.util.Collection;

import javax.crypto.SecretKey;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import com.bernardomg.example.spring.security.ws.jwt.security.authentication.jwt.configuration.JwtHttpSecurityConfigurer;
import com.bernardomg.example.spring.security.ws.jwt.security.entrypoint.ErrorResponseAccessDeniedHandler;
import com.bernardomg.example.spring.security.ws.jwt.security.entrypoint.ErrorResponseAuthenticationEntryPoint;
import com.bernardomg.example.spring.security.ws.jwt.security.property.JwtProperties;

import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;

/**
 * Web security configuration.
 *
 * @author Bernardo Mart&iacute;nez Garrido
 *
 */
@Configuration
@EnableWebSecurity
@Slf4j
public class WebSecurityConfig {

    /**
     * Default constructor.
     */
    public WebSecurityConfig() {
        super();
    }

    /**
     * JWT requests security.
     *
     * @param properties
     *            JWT properties
     * @param userDetailsService
     *            user details service
     * @return JWT requests security
     */
    @Bean
    public JwtHttpSecurityConfigurer getJwtSecurityConfigurer(final JwtProperties properties,
            final UserDetailsService userDetailsService) {
        final SecretKey key;

        key = Keys.hmacShaKeyFor(properties.getSecret()
            .getBytes(StandardCharsets.UTF_8));

        return new JwtHttpSecurityConfigurer(userDetailsService, key);
    }

    /**
     * Web security filter chain. Sets up all the authentication requirements for requests.
     *
     * @param http
     *            HTTP security component
     * @param introspector
     *            mapping introspector
     * @param securityConfigurers
     *            security configurers
     * @return web security filter chain with all authentication requirements
     * @throws Exception
     *             if the setup fails
     */
    @Bean("webSecurityFilterChain")
    public SecurityFilterChain getWebSecurityFilterChain(final HttpSecurity http,
            final HandlerMappingIntrospector introspector,
            final Collection<SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity>> securityConfigurers)
            throws Exception {
        final MvcRequestMatcher.Builder mvc;

        mvc = new MvcRequestMatcher.Builder(introspector);
        http
            // Whitelist access
            .authorizeHttpRequests(c -> c.requestMatchers(mvc.pattern("/actuator/**"), mvc.pattern("/login/**"))
                .permitAll())
            // Authenticate all others
            .authorizeHttpRequests(c -> c.anyRequest()
                .authenticated())
            // CSRF and CORS
            .csrf(CsrfConfigurer::disable)
            .cors(Customizer.withDefaults())
            // Authentication error handling
            .exceptionHandling(handler -> handler.accessDeniedHandler(new ErrorResponseAccessDeniedHandler())
                .authenticationEntryPoint(new ErrorResponseAuthenticationEntryPoint()))
            // Stateless
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            // Disable login and logout forms
            .formLogin(c -> c.disable())
            .logout(c -> c.disable());

        // Security configurers
        log.debug("Applying configurers: {}", securityConfigurers);
        for (final SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> securityConfigurer : securityConfigurers) {
            http.apply(securityConfigurer);
        }

        return http.build();
    }

}
