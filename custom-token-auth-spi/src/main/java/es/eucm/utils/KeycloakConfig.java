package es.eucm.utils;

import org.jboss.logging.Logger;

/**
 * Configuration provider for Keycloak OAuth2 connection settings.
 * 
 * <p>This class loads Keycloak configuration from environment variables,
 * providing the necessary parameters for OAuth2 authentication.</p>
 * 
 * <h2>Required Environment Variables</h2>
 * <ul>
 *   <li>{@code KEYCLOAK_TOKEN_URL} - Full URL to Keycloak's token endpoint
 *       (e.g., "https://keycloak.example.com/realms/simva/protocol/openid-connect/token")</li>
 *   <li>{@code KEYCLOAK_CLIENT_CLIENT_ID} - OAuth2 client ID registered in Keycloak</li>
 *   <li>{@code KEYCLOAK_CLIENT_CLIENT_SECRET} - OAuth2 client secret</li>
 * </ul>
 * 
 * <h2>Usage Example</h2>
 * <pre>
 * KeycloakConfig config = new KeycloakConfig();
 * String tokenUrl = config.getKeycloakTokenUrl();
 * </pre>
 * 
 * @author e-UCM Research Group
 * @see KeycloakOAuth2Client
 */
public class KeycloakConfig {
    private static final Logger logger = Logger.getLogger(KeycloakConfig.class);

    /** Environment variable name for Keycloak token URL */
    private static final String KEYCLOAK_TOKEN_URL = "KEYCLOAK_TOKEN_URL";
    
    /** Environment variable name for OAuth2 client ID */
    private static final String CLIENT_ID = "KEYCLOAK_CLIENT_CLIENT_ID";
    
    /** Environment variable name for OAuth2 client secret */
    private static final String CLIENT_SECRET = "KEYCLOAK_CLIENT_CLIENT_SECRET";

    private String keycloakTokenUrl;
    private String clientId;
    private String clientSecret;

    /**
     * Constructs a new KeycloakConfig by loading values from environment variables.
     */
    public KeycloakConfig() {
        this.keycloakTokenUrl = System.getenv(KEYCLOAK_TOKEN_URL);
        this.clientId = System.getenv(CLIENT_ID);
        this.clientSecret = System.getenv(CLIENT_SECRET);
    }

    /**
     * Returns the Keycloak token endpoint URL.
     * 
     * @return The token URL, or null if not configured
     */
    public String getKeycloakTokenUrl() {
        return this.keycloakTokenUrl;
    }

    /**
     * Returns the OAuth2 client ID.
     * 
     * @return The client ID, or null if not configured
     */
    public String getClientId() {
        return this.clientId;
    }

    /**
     * Returns the OAuth2 client secret.
     * 
     * @return The client secret, or null if not configured
     */
    public String getClientSecret() {
        return this.clientSecret;
    }

    /**
     * Prints all configuration values to the log for debugging.
     * Note: This will log sensitive information (client secret).
     */
    public void printConfig() {
        logger.info("Config values:");
        logger.info(KEYCLOAK_TOKEN_URL + ": " + (this.keycloakTokenUrl != null ? this.keycloakTokenUrl : "not set"));
        logger.info(CLIENT_ID + ": " + (this.clientId != null ? this.clientId : "not set"));
        logger.info(CLIENT_SECRET + ": " + (this.clientSecret != null ? this.clientSecret : "not set"));
    }
}