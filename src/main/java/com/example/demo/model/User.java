package com.example.demo.model;

import java.util.Date;
import java.util.List;

public class User {
    private String username;
    private String email;
    private Date birthdate;
    private List<String> roles;

    public User(String username, String email, Date birthdate, List<String> roles) {
        this.username = username;
        this.email = email;
        this.birthdate = birthdate;
        this.roles = roles;
    }

    public String getUsername() {
        return username;
    }

    public String getEmail() {
        return email;
    }

    public Date getBirthdate() {
        return birthdate;
    }

    public List<String> getRoles() {
        return roles;
    }
}
