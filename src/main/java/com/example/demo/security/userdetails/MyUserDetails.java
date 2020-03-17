package com.example.demo.security.userdetails;

import com.example.demo.model.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Date;
import java.util.List;

public class MyUserDetails extends User implements UserDetails {

    public MyUserDetails(String username, String email, Date birthdate, List<String> roles) {
        super(username, email, birthdate, roles);
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return AuthorityUtils.createAuthorityList(
                getRoles().stream().map(r -> "ROLE_" + r).toArray(String[]::new));
    }

    @Override
    public String getPassword() {
        return "n/a";
    }

    @Override
    public String getUsername() {
        return super.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
