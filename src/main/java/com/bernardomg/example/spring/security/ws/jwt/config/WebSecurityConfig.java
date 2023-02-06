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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;

import com.bernardomg.example.spring.security.ws.jwt.security.jwt.configuration.JwtSecurityConfigurer;
import com.bernardomg.example.spring.security.ws.jwt.security.token.validator.TokenValidator;

/**
 * Web security configuration.
 *
 * @author Bernardo Mart&iacute;nez Garrido
 *
 */
@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

    /**
     * Authentication entry point.
     */
    @Autowired
    private AuthenticationEntryPoint authenticationEntryPoint;

    /**
     * JWT token validator.
     */
    @Autowired
    private TokenValidator           tokenValidator;

    /**
     * User details service.
     */
    @Autowired
    private UserDetailsService       userDetailsService;

    public WebSecurityConfig() {
        super();
    }

    @Bean
    public SecurityFilterChain filterChain(final HttpSecurity http) throws Exception {
        final Customizer<ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry> authorizeRequestsCustomizer;
        final Customizer<FormLoginConfigurer<HttpSecurity>>                                                 formLoginCustomizer;
        final Customizer<LogoutConfigurer<HttpSecurity>>                                                    logoutCustomizer;

        // Authorization
        authorizeRequestsCustomizer = getAuthorizeRequestsCustomizer();
        // Login form
        formLoginCustomizer = c -> c.disable();
        // Logout
        logoutCustomizer = c -> c.disable();

        http.csrf()
            .disable()
            .cors()
            .and()
            .authorizeRequests(authorizeRequestsCustomizer)
            .formLogin(formLoginCustomizer)
            .logout(logoutCustomizer);

        http.userDetailsService(userDetailsService);

        // Applies JWT configuration
        http.apply(new JwtSecurityConfigurer(userDetailsService, tokenValidator));

        return http.build();
    }

    private final Customizer<ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry>
            getAuthorizeRequestsCustomizer() {
        return c -> {
            try {
                c.antMatchers("/actuator/**", "/token/**")
                    .permitAll()
                    .anyRequest()
                    .authenticated()
                    .and()
                    .exceptionHandling()
                    .authenticationEntryPoint(authenticationEntryPoint)
                    .and()
                    .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
            } catch (final Exception e) {
                // TODO Handle exception
                throw new RuntimeException(e);
            }
        };
    }

}
