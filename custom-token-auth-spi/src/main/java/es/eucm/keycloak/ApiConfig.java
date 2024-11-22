package es.eucm.keycloak;

import org.jboss.logging.Logger;

public class ApiConfig {
    private static final Logger logger = Logger.getLogger(ApiConfig.class);

    // Define configuration variables
    private static final String SIMVA_API_URL = "SIMVA_API_URL";
    private static final String SIMVA_API_ADMIN_USERNAME = "SIMVA_API_ADMIN_USERNAME";
    private static final String SIMVA_API_ADMIN_PASSWORD = "SIMVA_API_ADMIN_PASSWORD";

    private String simvaApiUrl;
    private String simvaApiAdminUsername;
    private String simvaApiAdminPassword;

    // Initialize the config from environment variables
    public ApiConfig() {
        this.simvaApiUrl = System.getenv(SIMVA_API_URL);
        this.simvaApiAdminUsername = System.getenv(SIMVA_API_ADMIN_USERNAME);
        this.simvaApiAdminPassword = System.getenv(SIMVA_API_ADMIN_PASSWORD);
        // Log environment variable loading
        //if (simvaApiUrl == null) {
        //    logger.warn(SIMVA_API_URL + " is not set.");
        //} else {
        //    logger.info(SIMVA_API_URL + " loaded: " + simvaApiUrl);
        //}
        //if (simvaApiAdminUsername == null) {
        //    logger.warn(SIMVA_API_ADMIN_USERNAME + " is not set.");
        //} else {
        //    logger.info(SIMVA_API_ADMIN_USERNAME + " loaded: " + simvaApiAdminUsername);
        //}
        //if (simvaApiAdminPassword == null) {
        //    logger.warn(SIMVA_API_ADMIN_PASSWORD + " is not set.");
        //} else {
        //    logger.info(SIMVA_API_ADMIN_PASSWORD + " loaded: " + simvaApiAdminPassword);
        //}
    }

    // Getters for each environment variable
    public String getApiUrl() {
        return simvaApiUrl;
    }

    public String getAdminUsername() {
        return simvaApiAdminUsername;
    }

    public String getAdminPassword() {
        return simvaApiAdminPassword;
    }

    // Utility method to print all variables (optional)
    public void printConfig() {
        logger.info("Config values:");
        logger.info(SIMVA_API_URL + ": " + (simvaApiUrl != null ? simvaApiUrl : "not set"));
        logger.info(SIMVA_API_ADMIN_USERNAME + ": " + (simvaApiAdminUsername != null ? simvaApiAdminUsername : "not set"));
        logger.info(SIMVA_API_ADMIN_PASSWORD + ": " + (simvaApiAdminPassword != null ? simvaApiAdminPassword : "not set"));
    }
}