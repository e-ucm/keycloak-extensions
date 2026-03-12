package es.eucm.utils;

import es.eucm.utils.SimvaApiConfig;

import org.jboss.logging.Logger;

import java.net.URL;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.List;
import java.util.HashMap;
import java.util.Collections;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.core.type.TypeReference;
import okhttp3.*;

/**
 * HTTP client for communicating with the SIMVA REST API.
 * 
 * <p>This client provides authenticated access to the SIMVA API, handling:
 * <ul>
 *   <li>OAuth2 token management via Keycloak</li>
 *   <li>Automatic token refresh using refresh tokens</li>
 *   <li>Admin and user authentication modes</li>
 *   <li>GET and POST requests with JSON payloads</li>
 * </ul>
 * 
 * <h2>Authentication Modes</h2>
 * <ul>
 *   <li><b>Admin Mode:</b> Authenticates using admin credentials from environment variables.
 *       Admin sessions are preserved across requests for connection pooling.</li>
 *   <li><b>User Mode:</b> Authenticates as a specific user. Session is cleared after use
 *       to avoid cross-user contamination.</li>
 * </ul>
 * 
 * <h2>Token Management</h2>
 * <p>The client implements intelligent token refresh:</p>
 * <ol>
 *   <li>Checks if current token is valid (with 30-second buffer before expiry)</li>
 *   <li>Attempts refresh using stored refresh token if available</li>
 *   <li>Falls back to credential-based authentication if refresh fails</li>
 * </ol>
 * 
 * <h2>Environment Variables</h2>
 * <ul>
 *   <li>{@code SIMVA_API_URL} - Base URL of the SIMVA API</li>
 *   <li>{@code SIMVA_API_ADMIN_USERNAME} - Admin username</li>
 *   <li>{@code SIMVA_API_ADMIN_PASSWORD} - Admin password</li>
 * </ul>
 * 
 * @author e-UCM Research Group
 * @see KeycloakOAuth2Client
 * @see SimvaApiConfig
 */
public class SimvaApiClient {
    private static final Logger logger = Logger.getLogger(SimvaApiClient.class);
    
    /** Shared Keycloak OAuth2 client for token operations */
    private static KeycloakOAuth2Client keycloakClient = new KeycloakOAuth2Client();

    /** Configuration loaded from environment variables */
    private static SimvaApiConfig apiConfig = new SimvaApiConfig();
    
    /** Current authenticated username */
    private String username;
    
    /** Current password (cleared after authentication) */
    private String password;
    
    /** Bearer token for API requests */
    private String bearerToken;
    
    /** OkHttp client for making HTTP requests */
    private OkHttpClient client;
    
    /** Flag indicating if this client is authenticated as admin */
    private boolean isAdminAuth = false;

    /**
     * Constructs a new SimvaApiClient with a fresh HTTP client instance.
     */
    public SimvaApiClient() {
        try {
            // Create a new HTTP client
            this.client = new OkHttpClient().newBuilder().build();
        } catch(Exception e) {
            logger.info(e.toString());
        }
    }

    /**
     * Checks if the client currently has a valid authentication token.
     * 
     * @return true if bearer token exists and is not expired
     */
    public boolean isAuthentificated() {
        return this.bearerToken != null && !keycloakClient.isTokenExpired();
    }

    /**
     * Check if the current token is expired or about to expire.
     * @return true if token needs refresh
     */
    public boolean isTokenExpired() {
        return keycloakClient.isTokenExpired();
    }

    /**
     * Check if the refresh token can be used to get a new access token.
     * @return true if refresh token is still valid
     */
    public boolean canUseRefreshToken() {
        return keycloakClient.canUseRefreshToken();
    }

    /**
     * Try to refresh the access token using the refresh token.
     * @return true if refresh was successful
     */
    public boolean refreshToken() throws IOException {
        boolean refreshed = keycloakClient.refreshAccessToken();
        if (refreshed) {
            this.bearerToken = "Bearer " + keycloakClient.getAccessToken();
            logger.info("Bearer token refreshed successfully");
        }
        return refreshed;
    }

    /**
     * Ensure admin is authenticated, using refresh token if available,
     * otherwise re-authenticating with credentials.
     * @return true if admin is authenticated (existing, refreshed, or new)
     */
    public boolean ensureAdminAuthenticated() throws IOException {
        // Token is still valid, no action needed
        if (this.isAdminAuth && this.isAuthentificated()) {
            logger.info("Admin already authenticated with valid token");
            return true;
        }
        
        // Token expired, try to refresh using refresh token first
        if (this.isAdminAuth && canUseRefreshToken()) {
            logger.info("Admin token expired, attempting to refresh using refresh token");
            if (refreshToken()) {
                logger.info("Admin token refreshed successfully");
                return true;
            }
            logger.info("Failed to refresh token, falling back to credentials");
        }
        
        // No valid token or refresh failed, authenticate with credentials
        logger.info("Authenticating admin with credentials");
        return authenticate();
    }

    /**
     * Authenticates using admin credentials from environment variables.
     * 
     * @return true if authentication succeeds
     * @throws IOException If authentication request fails
     */
    public boolean authenticate() throws IOException {
        boolean result = authenticate(apiConfig.getAdminUsername(), apiConfig.getAdminPassword());
        if (result) {
            this.isAdminAuth = true;
        }
        return result;
    }

    /**
     * Authenticates with specific username and password credentials.
     * 
     * <p>Obtains an OAuth2 access token from Keycloak using the
     * Resource Owner Password Credentials grant.</p>
     * 
     * @param username The username to authenticate with
     * @param password The password to authenticate with
     * @return true if authentication succeeds
     * @throws IOException If authentication request fails
     */
    public boolean authenticate(String username, String password) throws IOException {
        // Validate admin credentials to get a token
        boolean isValid = keycloakClient.validateUserCredentials(username, password);
        if(!isValid) {
            logger.info("Invalid credentials for Simva API");
            return false;
        } else {
            logger.info("Credentials validated");
            this.username = username;
            this.password = password;
            // Store the bearer token for future requests
            this.bearerToken = "Bearer " + keycloakClient.getAccessToken();
            logger.info("Token: " + this.bearerToken);
            return true;
        }
    }

    /**
     * Authenticate as an already verified user using admin impersonation.
     * Used when user is already authenticated in Keycloak browser session.
     * Falls back to admin authentication if impersonation fails.
     * Only re-authenticates if token is expired.
     * 
     * @param username The username of the already authenticated user
     * @return true if authentication succeeded
     */
    public boolean authenticateAsUser(String username) throws IOException {
        // First ensure admin is authenticated (only re-auth if token expired)
        boolean adminAuth = ensureAdminAuthenticated();
        if (!adminAuth) {
            logger.info("Failed to authenticate as admin for user impersonation");
            return false;
        }
        
        // Store the username we're acting on behalf of
        this.username = username;
        logger.info("Authenticated as admin on behalf of user: " + username);
        return true;
    }

    /**
     * Disconnects the current session.
     * 
     * <p>For admin sessions, only clears user context while preserving
     * the admin authentication. For user sessions, fully disconnects.</p>
     * 
     * @return true if disconnect succeeds
     * @throws IOException If logout request fails
     */
    public boolean disconnect() throws IOException {
        // Only disconnect if not admin auth (preserve admin session)
        if (!this.isAdminAuth) {
            this.keycloakClient.disconnect();
            this.bearerToken = null;
            logger.info("Disconnected from SIMVA API");
        }
        this.username = null;
        this.password = null;
        return true;
    }

    /**
     * Forces a complete disconnect, including admin sessions.
     * 
     * <p>Use this when you need to completely clear all authentication
     * state, for example during error recovery.</p>
     * 
     * @return true if disconnect succeeds
     * @throws IOException If logout request fails
     */
    public boolean forceDisconnect() throws IOException {
        this.keycloakClient.disconnect();
        this.username = null;
        this.password = null;
        this.bearerToken = null;
        this.isAdminAuth = false;
        return true;
    }

    /**
     * Sends an authenticated GET request to the SIMVA API.
     * 
     * @param concat_url The path to append to the base API URL (e.g., "/studies/123")
     * @return Parsed JSON response as a Map, or empty map for unexpected structures
     * @throws IOException If the request fails
     */
    public Map<String, Object> sendGetRequest(String concat_url) throws IOException {
        // Construct the URL
        String urlString = apiConfig.getApiUrl() + concat_url;
        logger.info("urlString: " + urlString);
        URL url = new URL(urlString);
        // Build the request object, with method, headers
        Request request;
        if(this.isAuthentificated()) {
            request = new Request.Builder()
                .url(urlString)
                .get()
                .addHeader("Authorization", this.bearerToken)
                .addHeader("Content-Type", "application/json")
                .build();
        } else {
             request = new Request.Builder()
                .url(urlString)
                .get()
                .addHeader("Content-Type", "application/json")
                .build();
        }
        // Perform the request, this potentially throws an IOException
        Response response = this.client.newCall(request).execute();
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode jsonNode = objectMapper.readTree(response.body().byteStream());
        return this.parseJson(objectMapper, jsonNode);
    }

    /**
     * Parses a JSON response into a Map structure.
     * 
     * <p>Handles both array and object responses:</p>
     * <ul>
     *   <li>Arrays are converted to Maps with string index keys ("0", "1", etc.)</li>
     *   <li>Objects are directly converted to Maps</li>
     * </ul>
     * 
     * @param objectMapper The Jackson ObjectMapper instance
     * @param jsonNode The parsed JSON node
     * @return Map representation of the JSON, or empty map for unexpected types
     */
    public Map<String, Object> parseJson(ObjectMapper objectMapper, JsonNode jsonNode) {
        if (jsonNode.isArray()) {
            List<Map<String, Object>> responseList = objectMapper.convertValue(jsonNode, new TypeReference<>() {});
            Map<String, Object> result = new HashMap<>();
            for (int i = 0; i < responseList.size(); i++) {
                result.put(String.valueOf(i), responseList.get(i)); // Use index as key
            }
            logger.info("Parsed as a List, converted to Map: " + result);
            return result;
        } else if (jsonNode.isObject()) {
            Map<String, Object> responseMap = objectMapper.convertValue(jsonNode, new TypeReference<>() {});
            logger.info("Parsed as a Map: " + responseMap);
            return responseMap;
        } else {
            logger.info("Unexpected JSON structure: " + jsonNode);
            return Collections.emptyMap(); // Return an empty map for unexpected cases
        }
    }

    /**
     * Sends an authenticated POST request to the SIMVA API with a JSON body.
     * 
     * @param concat_url The path to append to the base API URL
     * @param jsonBody The JSON string to send as the request body
     * @return Parsed JSON response as a Map
     * @throws IOException If the request fails
     */
    public Map<String, Object> sendPostRequest(String concat_url, String jsonBody) throws IOException {
        // Construct the URL
        String urlString = apiConfig.getApiUrl() + concat_url;
        logger.info("urlString: " + urlString);
        URL url = new URL(urlString);

        // Create the request body
        MediaType mediaType = MediaType.parse("application/json");
        RequestBody body = RequestBody.create(jsonBody, mediaType);
        // Build the request object, with method, headers
        Request request;
        if(this.isAuthentificated()) {
            request = new Request.Builder()
                    .url(urlString)
                    .method("POST", body)
                    .addHeader("Authorization", this.bearerToken)
                    .addHeader("Content-Type", "application/json")
                    .build();   
        } else {
            request = new Request.Builder()
                .url(urlString)
                .method("POST", body)
                .addHeader("Content-Type", "application/json")
                .build();
        }

        // Perform the request, this potentially throws an IOException
        Response response = this.client.newCall(request).execute();
        // Read the body of the response into a map
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode jsonNode = objectMapper.readTree(response.body().byteStream());
        return this.parseJson(objectMapper, jsonNode);
    }

    /**
     * Checks if SIMVA API is running SQL version by querying the health endpoint.
     * 
     * <p>The SQL version is indicated by {@code db.status = true} in the
     * {@code /health} endpoint response.</p>
     * 
     * @return true if SQL version, false if NoSQL version or unable to determine
     */
    public Boolean checkSQLVersion() {
        try {
            Map<String, Object> versionInfo = this.sendGetRequest("/health");
            if(versionInfo.containsKey("db") && versionInfo.get("db") instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> dbInfo = (Map<String, Object>) versionInfo.get("db");
                if(dbInfo.containsKey("status")) {
                    return (Boolean) dbInfo.get("status");
                }
            }
            logger.info("Version info does not contain 'db.status' key: " + versionInfo);
            return false;
        } catch (IOException e) {
            logger.info("Error checking SIMVA API version: " + e.toString());
            return false;
        }
    }
}