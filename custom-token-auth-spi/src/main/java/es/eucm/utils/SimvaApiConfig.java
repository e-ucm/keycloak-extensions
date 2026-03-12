package es.eucm.utils;

import org.jboss.logging.Logger;

/**
 * Configuration provider for SIMVA API connection settings.
 * 
 * <p>This class loads SIMVA API configuration from environment variables,
 * providing a centralized way to access connection parameters.</p>
 * 
 * <h2>Required Environment Variables</h2>
 * <ul>
 *   <li>{@code SIMVA_API_URL} - Base URL of the SIMVA REST API
 *       (e.g., "https://simva.example.com/api")</li>
 *   <li>{@code SIMVA_API_ADMIN_USERNAME} - Admin account username for privileged operations</li>
 *   <li>{@code SIMVA_API_ADMIN_PASSWORD} - Admin account password</li>
 * </ul>
 * 
 * <h2>Usage Example</h2>
 * <pre>
 * SimvaApiConfig config = new SimvaApiConfig();
 * String apiUrl = config.getApiUrl();
 * </pre>
 * 
 * @author e-UCM Research Group
 * @see SimvaApiClient
 */
public class SimvaApiConfig {
    private static final Logger logger = Logger.getLogger(SimvaApiConfig.class);

    /** Environment variable name for SIMVA API URL */
    private static final String SIMVA_API_URL = "SIMVA_API_URL";
    
    /** Environment variable name for admin username */
    private static final String SIMVA_API_ADMIN_USERNAME = "SIMVA_API_ADMIN_USERNAME";
    
    /** Environment variable name for admin password */
    private static final String SIMVA_API_ADMIN_PASSWORD = "SIMVA_API_ADMIN_PASSWORD";

    private String simvaApiUrl;
    private String simvaApiAdminUsername;
    private String simvaApiAdminPassword;

    /**
     * Constructs a new SimvaApiConfig by loading values from environment variables.
     */
    public SimvaApiConfig() {
        this.simvaApiUrl = System.getenv(SIMVA_API_URL);
        this.simvaApiAdminUsername = System.getenv(SIMVA_API_ADMIN_USERNAME);
        this.simvaApiAdminPassword = System.getenv(SIMVA_API_ADMIN_PASSWORD);
    }

    /**
     * Returns the SIMVA API base URL.
     * 
     * @return The API URL, or null if not configured
     */
    public String getApiUrl() {
        return simvaApiUrl;
    }

    /**
     * Returns the admin username for SIMVA API.
     * 
     * @return The admin username, or null if not configured
     */
    public String getAdminUsername() {
        return simvaApiAdminUsername;
    }

    /**
     * Returns the admin password for SIMVA API.
     * 
     * @return The admin password, or null if not configured
     */
    public String getAdminPassword() {
        return simvaApiAdminPassword;
    }

    /**
     * Prints all configuration values to the log for debugging.
     * Note: This will log sensitive information (passwords).
     */
    public void printConfig() {
        logger.info("Config values:");
        logger.info(SIMVA_API_URL + ": " + (simvaApiUrl != null ? simvaApiUrl : "not set"));
        logger.info(SIMVA_API_ADMIN_USERNAME + ": " + (simvaApiAdminUsername != null ? simvaApiAdminUsername : "not set"));
        logger.info(SIMVA_API_ADMIN_PASSWORD + ": " + (simvaApiAdminPassword != null ? simvaApiAdminPassword : "not set"));
    }
}