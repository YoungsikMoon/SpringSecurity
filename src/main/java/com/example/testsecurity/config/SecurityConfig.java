package com.example.testsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

  @Bean
  public BCryptPasswordEncoder bCryptPasswordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  public RoleHierarchyImpl roleHierarchy() {
    return RoleHierarchyImpl.fromHierarchy("""
        ROLE_A > ROLE_B
        ROLE_B > ROLE_C
        """);
  }

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
    http

        .authorizeHttpRequests((auth) -> auth
            .requestMatchers("/", "/login", "/join", "/joinProc", "/logout").permitAll()
            .requestMatchers("/admin/**").hasRole("ADMIN")
            .requestMatchers("/my/**").hasAnyRole("USER")
            .anyRequest().authenticated()
        );

    http
        .formLogin((auth) -> auth
            .loginPage("/login")
            .loginProcessingUrl("/loginProc")
            .defaultSuccessUrl("/")
            .permitAll()
        );

//    http
//        .httpBasic(Customizer.withDefaults());

    http
        .csrf((auth) -> auth.disable());

    http
        .logout((auth) -> auth
            .logoutUrl("/logout")
            .logoutSuccessUrl("/"));

    http
        .sessionManagement((auth) -> auth
            .sessionFixation().changeSessionId()
            .maximumSessions(1)
            .maxSessionsPreventsLogin(true)
        );

    return http.build();
  }

}