package com.example.demo;

import com.example.demo.config.KeycloakExtension;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.representations.info.ServerInfoRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.RestTemplate;

import javax.ws.rs.core.Response;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(KeycloakExtension.class)
@SpringBootTest(properties = {"spring.security.oauth2.resourceserver.jwt.issuer-uri=${KEYCLOAK_ISSUER_URI}"})
@AutoConfigureMockMvc
@ActiveProfiles("test")
@DisplayName("oauth resource server tests")
public class OAuthResourceServerTests {

    private static final Logger logger = LoggerFactory.getLogger(OAuthResourceServerTests.class);

    @Autowired
    private MockMvc mvc;

    private final KeycloakContainer keycloakContainer;

    public OAuthResourceServerTests(KeycloakContainer keycloakContainer) {
        this.keycloakContainer = keycloakContainer;
    }

    @Test
    @DisplayName("admin client setup successful")
    public void keycloakInternals() {
        Keycloak keycloakAdminClient = KeycloakBuilder.builder()
                .serverUrl(keycloakContainer.getAuthServerUrl())
                .realm("master")
                .clientId("admin-cli")
                .username("admin")
                .password("admin")
                .build();

        ServerInfoRepresentation serverInfo = keycloakAdminClient.serverInfo().getInfo();
        assertThat(serverInfo).isNotNull();

        var users = keycloakAdminClient.realm("master").users().list();
        assertThat(users).isNotEmpty();
        assertThat(serverInfo.getSystemInfo().getVersion()).isEqualTo("10.0.2"); // TODO: read from properties
    }

    @Test
    @DisplayName("keycloak user created in realm \"demo\"")
    public void createUser() {
        Keycloak keycloakAdminClient = KeycloakBuilder.builder()
                .serverUrl(keycloakContainer.getAuthServerUrl())
                .realm("master")
                .clientId("admin-cli")
                .username("admin")
                .password("admin")
                .build();

        UserRepresentation user = createKeycloakUserRepresentation("oliver", "mys3cret");
        Response res = keycloakAdminClient.realm("demo").users().create(user);
        res.close();
        assertThat(res.getStatus()).isEqualTo(201);

        var users = keycloakAdminClient.realm("demo").users().list();
        assertThat(users).isNotEmpty();
    }

    @Test
    @DisplayName("valid access token is accepted")
    public void validOAuthJwtShouldReturnUsername() throws Exception {
        Keycloak keycloakAdminClient = KeycloakBuilder.builder()
                .serverUrl(keycloakContainer.getAuthServerUrl())
                .realm("master")
                .clientId("admin-cli")
                .username("admin")
                .password("admin")
                .build();

        // create user and set credentials
        UserRepresentation user = createKeycloakUserRepresentation("olivia.oauth", "myAw3s0mes3cret");
        user.setEmail("olivia.oauth@test.local");
        user.setFirstName("Olivia");
        user.setLastName("OAuth");

        Response res = keycloakAdminClient.realm("demo").users().create(user);
        res.close();
        assertThat(res.getStatus()).isEqualTo(201);

        // get access token from token endpoint
        String tokenEndpoint = keycloakContainer.getAuthServerUrl() + "/realms/demo/protocol/openid-connect/token";
        var restTemplate = new RestTemplate();
        var headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        var map = new LinkedMultiValueMap<>();
        map.add("grant_type", "password");
        map.add("client_id", "openid-connect-client");
        map.add("username", "olivia.oauth");
        map.add("password", "myAw3s0mes3cret");
        var token = restTemplate.postForObject(tokenEndpoint, new HttpEntity<>(map, headers), KeycloakToken.class);
        assertThat(token).isNotNull();

        String accessToken = token.getAccessToken();

        mvc.perform(MockMvcRequestBuilders.get("/whoami")
                .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(content().json("{'whoami': 'olivia.oauth@test.local'}"));
    }

    @Test
    @DisplayName("unknown user with valid token is unauthorized")
    public void invalidOAuthJwtShouldReturnUnauthorized() throws Exception {
        Keycloak keycloakAdminClient = KeycloakBuilder.builder()
                .serverUrl(keycloakContainer.getAuthServerUrl())
                .realm("master")
                .clientId("admin-cli")
                .username("admin")
                .password("admin")
                .build();

        // create user and set credentials
        UserRepresentation user = createKeycloakUserRepresentation("james.oauth", "passw0rd");
        user.setEmail("james.oauth@domain.local");

        Response res = keycloakAdminClient.realm("demo").users().create(user);
        res.close();
        assertThat(res.getStatus()).isEqualTo(201);

        // get access token from token endpoint
        String tokenEndpoint = keycloakContainer.getAuthServerUrl() + "/realms/demo/protocol/openid-connect/token";
        var restTemplate = new RestTemplate();
        var headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        var map = new LinkedMultiValueMap<>();
        map.add("grant_type", "password");
        map.add("client_id", "openid-connect-client");
        map.add("username", "james.oauth");
        map.add("password", "passw0rd");
        var token = restTemplate.postForObject(tokenEndpoint, new HttpEntity<>(map, headers), KeycloakToken.class);
        assertThat(token).isNotNull();

        String accessToken = token.getAccessToken();
        logger.info(accessToken);

        mvc.perform(MockMvcRequestBuilders.get("/whoami")
                .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isUnauthorized());
    }

    private UserRepresentation createKeycloakUserRepresentation(String username, String password) {
        UserRepresentation user = new UserRepresentation();
        user.setUsername(username);
        CredentialRepresentation credentials = new CredentialRepresentation();
        credentials.setType(CredentialRepresentation.PASSWORD);
        credentials.setValue(password);
        credentials.setTemporary(false);
        user.setCredentials(Collections.singletonList(credentials));
        user.setEnabled(true);
        return user;
    }

    private static class KeycloakToken {
        private String accessToken;

        @JsonCreator
        KeycloakToken(@JsonProperty("access_token") final String accessToken) {
            this.accessToken = accessToken;
        }

        public String getAccessToken() {
            return accessToken;
        }
    }

}
