package com.example.demo.security;

import com.example.demo.security.userdetails.MyUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private final MyUserDetailsService myUserDetailsService;

    public WebSecurityConfig(MyUserDetailsService myUserDetailsService) {
        this.myUserDetailsService = myUserDetailsService;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                .authorizeRequests()
                .antMatchers("/health").permitAll()
                .antMatchers("/token/create").permitAll()
                .anyRequest().authenticated().and()
                .csrf().disable()
                .httpBasic().and()
                .oauth2ResourceServer().jwt()
                .jwtAuthenticationConverter(oAuthJwtAuthenticationConverter())
        ;
    }

    @Bean
    OAuthJwtAuthenticationConverter oAuthJwtAuthenticationConverter() {
        return new OAuthJwtAuthenticationConverter(myUserDetailsService);
    }

    @Bean
    StaticJwtAuthenticationProvider staticJwtAuthenticationProvider() {
        return new StaticJwtAuthenticationProvider(new StaticJwtAuthenticationConverter(myUserDetailsService));
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(staticJwtAuthenticationProvider());
        auth.userDetailsService(myUserDetailsService);
        auth.inMemoryAuthentication()
                .withUser("basicUser")
                .password(passwordEncoder().encode("password"))
                .roles("USER");
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
