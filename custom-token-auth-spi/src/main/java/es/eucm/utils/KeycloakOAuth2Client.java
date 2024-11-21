package es.eucm.utils;

import es.eucm.utils.KeycloakConfig;

import org.jboss.logging.Logger;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.*;

import java.io.IOException;

public class KeycloakOAuth2Client {
    private static final Logger logger = Logger.getLogger(KeycloakOAuth2Client.class);

    private static final OkHttpClient sharedHttpClient = new OkHttpClient(); // Singleton instance
    private static final KeycloakConfig apiConfig = new KeycloakConfig();
    private final ObjectMapper objectMapper;
    private String accessToken;
    private String refreshToken;

    public KeycloakOAuth2Client() {
        this.objectMapper = new ObjectMapper();
    }

    public boolean validateUserCredentials(String username, String password) throws IOException {
        logger.info("validateUserCredentials : " + username);
        RequestBody formBody = new FormBody.Builder()
                .add("grant_type", "password")
                .add("client_id", apiConfig.getClientId())
                .add("client_secret", apiConfig.getClientSecret())
                .add("username", username)
                .add("password", password)
                .build();

        Request request = new Request.Builder()
                .url(apiConfig.getKeycloakTokenUrl())
                .post(formBody)
                .build();

        try (Response response = sharedHttpClient.newCall(request).execute()) { // Use shared instance
            if (response.isSuccessful()) {
                String responseBody = response.body().string();
                JsonNode jsonNode = objectMapper.readTree(responseBody);
                this.accessToken = jsonNode.get("access_token").asText();
                this.refreshToken = jsonNode.get("refresh_token").asText();
                logger.info("Access Token: Bearer " + this.accessToken);
                return true;
            } else {
                logger.info("Error: " + response.code() + " - " + response.body().string());
                return false;
            }
        }
    }

    public boolean disconnect() throws IOException {

        if (this.accessToken != null) {
            RequestBody formBody = new FormBody.Builder()
                .add("grant_type", "refresh_token")
                .add("client_id", apiConfig.getClientId())
                .add("client_secret", apiConfig.getClientSecret())
                .add("refresh_token", this.refreshToken)
                .build();

            Request request = new Request.Builder()
                .url(apiConfig.getKeycloakTokenUrl().replace("/token", "/logout"))
                //.header("Authorization", "Bearer " + this.accessToken)  // Add authorization header
                .post(formBody)
                .build();
            
            try (Response response = sharedHttpClient.newCall(request).execute()) { // Use shared instance
                if (response.isSuccessful()) {
                    logger.info("Disconnecting and invalidating access token.");
                    this.accessToken = null;
                    this.refreshToken = null;
                    sharedHttpClient.connectionPool().evictAll();
                    sharedHttpClient.dispatcher().executorService().shutdown();
                    logger.info("OkHttpClient resources cleaned up.");
                    return true;
                } else {
                    logger.info("Error: " + response.code() + " - " + response.body().string());
                    return false;
                }
            }
        } else {
            return true;
        }  
    } 
}
