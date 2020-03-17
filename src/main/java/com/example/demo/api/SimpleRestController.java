package com.example.demo.api;

import com.example.demo.helpers.StaticJwtCreator;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
class SimpleRestController {

    private final StaticJwtCreator utils;

    SimpleRestController(StaticJwtCreator utils) {
        this.utils = utils;
    }

    @GetMapping(value = "/token/create", produces = MediaType.APPLICATION_JSON_VALUE)
    public String createToken() {
        return "{\"value\": \"" + utils.createToken() + "\"}";
    }

    @GetMapping(value = "/whoami", produces = MediaType.APPLICATION_JSON_VALUE)
    public String whoami(Principal principal) {
        return "{\"whoami\": \"" + principal.getName() + "\"}";
    }

    @GetMapping(value = "/health", produces = MediaType.APPLICATION_JSON_VALUE)
    public String noSecurity() {
        return "{\"health\": \"ok\"}";
    }

}
