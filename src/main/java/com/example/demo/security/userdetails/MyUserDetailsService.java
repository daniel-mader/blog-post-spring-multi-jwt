package com.example.demo.security.userdetails;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.Date;
import java.util.List;

@Service
public class MyUserDetailsService implements UserDetailsService {

    Logger logger = LoggerFactory.getLogger(MyUserDetailsService.class);

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        logger.info("Loading user details for user {} ...", username);

        // Access some user database here ...

        List<String> allowedUsers = Arrays.asList("basicUser", "staticUser", "olivia.oauth@test.local");
        if (allowedUsers.contains(username)) {
            return new MyUserDetails(username, username + "@email.local", new Date(992182578), Arrays.asList("EDITOR", "VIEWER"));
        } else {
            throw new UsernameNotFoundException(String.format("Username not found: %s", username));
        }
    }
}
