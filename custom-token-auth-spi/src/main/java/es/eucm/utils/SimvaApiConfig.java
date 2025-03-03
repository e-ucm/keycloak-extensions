package es.eucm.utils;

import org.jboss.logging.Logger;

public class SimvaApiConfig {
    private static final Logger logger = Logger.getLogger(SimvaApiConfig.class);

    // Define configuration variables
    private static final String SIMVA_API_URL = "SIMVA_API_URL";
    private static final String SIMVA_API_ADMIN_USERNAME = "SIMVA_API_ADMIN_USERNAME";
    private static final String SIMVA_API_ADMIN_PASSWORD = "SIMVA_API_ADMIN_PASSWORD";

    private String simvaApiUrl;
    private String simvaApiAdminUsername;
    private String simvaApiAdminPassword;

    // Initialize the config from environment variables
    public SimvaApiConfig() {
        this.simvaApiUrl = System.getenv(SIMVA_API_URL);
        this.simvaApiAdminUsername = System.getenv(SIMVA_API_ADMIN_USERNAME);
        this.simvaApiAdminPassword = System.getenv(SIMVA_API_ADMIN_PASSWORD);
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