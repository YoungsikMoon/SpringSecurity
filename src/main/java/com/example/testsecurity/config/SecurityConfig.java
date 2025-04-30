package com.example.testsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
    http.authorizeHttpRequests((auth) -> auth
            .requestMatchers("/", "/login").permitAll() //모든 유저
            .requestMatchers("/admin").hasRole("ADMIN") // 어드민만
            .requestMatchers("/my/**").hasAnyRole("ADMIN", "USER") //어드민 또는 유저만
            .anyRequest().authenticated() // 나머지 ,로그인한 사용자만 접근하도록
        );
    return http.build();
  }
}