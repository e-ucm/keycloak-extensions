package es.eucm.utils;

import org.jboss.logging.Logger;

public class KeycloakConfig {
    private static final Logger logger = Logger.getLogger(KeycloakConfig.class);

    // Define configuration variables
    private static final String KEYCLOAK_TOKEN_URL = "KEYCLOAK_TOKEN_URL";
    private static final String CLIENT_ID = "KEYCLOAK_CLIENT_CLIENT_ID";
    private static final String CLIENT_SECRET = "KEYCLOAK_CLIENT_CLIENT_SECRET";

    private String keycloakTokenUrl;
    private String clientId;
    private String clientSecret;

    // Initialize the config from environment variables
    public KeycloakConfig() {
        this.keycloakTokenUrl = System.getenv(KEYCLOAK_TOKEN_URL);
        this.clientId = System.getenv(CLIENT_ID);
        this.clientSecret = System.getenv(CLIENT_SECRET);
    }

    // Getters for each environment variable
    public String getKeycloakTokenUrl() {
        return this.keycloakTokenUrl;
    }

    public String getClientId() {
        return this.clientId;
    }

    public String getClientSecret() {
        return this.clientSecret;
    }

    // Utility method to print all variables (optional)
    public void printConfig() {
        logger.info("Config values:");
        logger.info(KEYCLOAK_TOKEN_URL + ": " + (this.keycloakTokenUrl != null ? this.keycloakTokenUrl : "not set"));
        logger.info(CLIENT_ID + ": " + (this.clientId != null ? this.clientId : "not set"));
        logger.info(CLIENT_SECRET + ": " + (this.clientSecret != null ? this.clientSecret : "not set"));
    }
}