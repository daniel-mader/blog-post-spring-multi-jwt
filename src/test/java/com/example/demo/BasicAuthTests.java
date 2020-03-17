package com.example.demo;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@DisplayName("basic authentication tests")
public class BasicAuthTests {

    @Autowired
    private MockMvc mvc;

    @Value("${basicAuth}")
    private String basicAuth;

    @Test
    @DisplayName("access denied when no authentication")
    public void noTokenShouldReturnUnauthorized() throws Exception {
        mvc.perform(MockMvcRequestBuilders.get("/whoami"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("valid basic authentication")
    public void validBasicAuthShouldReturnUsername() throws Exception {
        mvc.perform(MockMvcRequestBuilders.get("/whoami")
                .header("Authorization", "Basic " + basicAuth))
                .andExpect(status().isOk())
                .andExpect(content().json("{'whoami': 'basicUser'}"));
    }

    @Test
    @DisplayName("access denied when invalid authentication")
    public void invalidBasicAuthReturnUnauthorized() throws Exception {
        mvc.perform(MockMvcRequestBuilders.get("/whoami")
                .header("Authorization", "Basic " + "inv4lid"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("endpoint allows no security")
    public void noTokenIsValidOnNoSecEndpoint() throws Exception {
        mvc.perform(MockMvcRequestBuilders.get("/health"))
                .andExpect(status().isOk());
    }

}
