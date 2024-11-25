package es.eucm.keycloak.authentificators.utils;

import es.eucm.keycloak.authentificators.utils.KeycloakConfig;

import org.jboss.logging.Logger;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.*;

import java.io.IOException;

public class KeycloakOAuth2Client {
    private static final Logger logger = Logger.getLogger(KeycloakOAuth2Client.class);

    private KeycloakConfig apiConfig;
    private final OkHttpClient httpClient;
    private final ObjectMapper objectMapper;

    public KeycloakOAuth2Client() {
        this.apiConfig = new KeycloakConfig();
        this.apiConfig.printConfig();
        this.httpClient = new OkHttpClient();
        this.objectMapper = new ObjectMapper();
    }

    public boolean validateUserCredentials(String username, String password) throws IOException {
        logger.info("validateUserCredentials : " + username);
        RequestBody formBody = new FormBody.Builder()
                .add("grant_type", "password")
                .add("client_id", this.apiConfig.getClientId())
                .add("client_secret", this.apiConfig.getClientSecret())
                .add("username", username)
                .add("password", password)
                .build();

        Request request = new Request.Builder()
                .url(this.apiConfig.getKeycloakTokenUrl())
                .post(formBody)
                .build();

        try (Response response = httpClient.newCall(request).execute()) {
            if (response.isSuccessful()) {
                // If we receive an access token, the credentials are valid
                String responseBody = response.body().string();
                JsonNode jsonNode = objectMapper.readTree(responseBody);
                String accessToken = jsonNode.get("access_token").asText();
                logger.info("Access Token: " + accessToken);
                return true;
            } else {
                // Invalid credentials or other error
                logger.info("Error: " + response.code() + " - " + response.body().string());
                return false;
            }
        }
    }
}
