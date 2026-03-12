package es.eucm.utils;

import es.eucm.utils.KeycloakConfig;

import org.jboss.logging.Logger;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.*;

import java.io.IOException;

/**
 * OAuth2 client for obtaining and managing access tokens from Keycloak.
 * 
 * <p>This client handles the OAuth2 Resource Owner Password Credentials (ROPC)
 * grant type for authenticating users and obtaining JWT access tokens.</p>
 * 
 * <h2>Token Lifecycle Management</h2>
 * <p>The client tracks token expiration times and provides methods for:</p>
 * <ul>
 *   <li>Checking if the current token is expired (with configurable buffer)</li>
 *   <li>Checking if the refresh token is still valid</li>
 *   <li>Refreshing the access token using the refresh token</li>
 * </ul>
 * 
 * <h2>Expiration Buffer</h2>
 * <p>A 30-second buffer ({@link #TOKEN_EXPIRY_BUFFER_MS}) is used before the actual
 * expiration time to account for network latency and ensure tokens don't expire
 * mid-request.</p>
 * 
 * <h2>Environment Variables Required</h2>
 * <ul>
 *   <li>{@code KEYCLOAK_TOKEN_URL} - Full URL to Keycloak's token endpoint</li>
 *   <li>{@code KEYCLOAK_CLIENT_CLIENT_ID} - OAuth2 client ID</li>
 *   <li>{@code KEYCLOAK_CLIENT_CLIENT_SECRET} - OAuth2 client secret</li>
 * </ul>
 * 
 * @author e-UCM Research Group
 * @see KeycloakConfig
 * @see SimvaApiClient
 */
public class KeycloakOAuth2Client {
    private static final Logger logger = Logger.getLogger(KeycloakOAuth2Client.class);

    /** Shared OkHttp client instance for connection pooling */
    private static final OkHttpClient sharedHttpClient = new OkHttpClient();
    
    /** Configuration loaded from environment variables */
    private static final KeycloakConfig apiConfig = new KeycloakConfig();
    
    /** Jackson ObjectMapper for JSON parsing */
    private final ObjectMapper objectMapper;
    
    /** Current OAuth2 access token */
    private String accessToken;
    
    /** Current OAuth2 refresh token */
    private String refreshToken;
    
    /** Unix timestamp (ms) when access token expires */
    private long tokenExpirationTime;
    
    /** Unix timestamp (ms) when refresh token expires */
    private long refreshTokenExpirationTime;
    
    /** Buffer time (30 seconds) before token expiry to trigger refresh */
    private static final long TOKEN_EXPIRY_BUFFER_MS = 30000;
    
    /** Default refresh token lifetime (30 minutes) if not specified in response */
    private static final long REFRESH_TOKEN_DEFAULT_EXPIRY_MS = 1800000;

    /**
     * Returns the current access token.
     * 
     * @return The JWT access token string, or null if not authenticated
     */
    public String getAccessToken() {
        return this.accessToken;
    }

    /**
     * Check if the current token is expired or about to expire.
     * @return true if token is expired or will expire within the buffer time
     */
    public boolean isTokenExpired() {
        if (this.accessToken == null) {
            return true;
        }
        return System.currentTimeMillis() >= (tokenExpirationTime - TOKEN_EXPIRY_BUFFER_MS);
    }

    /**
     * Check if the refresh token is still valid.
     * @return true if refresh token can be used
     */
    public boolean canUseRefreshToken() {
        if (this.refreshToken == null) {
            return false;
        }
        return System.currentTimeMillis() < (refreshTokenExpirationTime - TOKEN_EXPIRY_BUFFER_MS);
    }

    /**
     * Get the token expiration time in milliseconds.
     * @return Unix timestamp when token expires
     */
    public long getTokenExpirationTime() {
        return this.tokenExpirationTime;
    }

    /**
     * Refresh the access token using the refresh token.
     * @return true if refresh was successful
     */
    public boolean refreshAccessToken() throws IOException {
        if (!canUseRefreshToken()) {
            logger.info("Refresh token is expired or not available");
            return false;
        }

        logger.info("Attempting to refresh access token");
        RequestBody formBody = new FormBody.Builder()
                .add("grant_type", "refresh_token")
                .add("client_id", apiConfig.getClientId())
                .add("client_secret", apiConfig.getClientSecret())
                .add("refresh_token", this.refreshToken)
                .build();

        Request request = new Request.Builder()
                .url(apiConfig.getKeycloakTokenUrl())
                .post(formBody)
                .build();

        try (Response response = sharedHttpClient.newCall(request).execute()) {
            if (response.isSuccessful()) {
                String responseBody = response.body().string();
                JsonNode jsonNode = objectMapper.readTree(responseBody);
                this.accessToken = jsonNode.get("access_token").asText();
                this.refreshToken = jsonNode.get("refresh_token").asText();
                
                // Calculate token expiration time
                int expiresIn = jsonNode.has("expires_in") ? jsonNode.get("expires_in").asInt() : 300;
                this.tokenExpirationTime = System.currentTimeMillis() + (expiresIn * 1000L);
                
                // Calculate refresh token expiration time
                int refreshExpiresIn = jsonNode.has("refresh_expires_in") ? 
                    jsonNode.get("refresh_expires_in").asInt() : (int)(REFRESH_TOKEN_DEFAULT_EXPIRY_MS / 1000);
                this.refreshTokenExpirationTime = System.currentTimeMillis() + (refreshExpiresIn * 1000L);
                
                logger.info("Token refreshed successfully, expires in " + expiresIn + " seconds");
                return true;
            } else {
                logger.info("Failed to refresh token: " + response.code() + " - " + response.body().string());
                // Clear refresh token since it's no longer valid
                this.refreshToken = null;
                this.refreshTokenExpirationTime = 0;
                return false;
            }
        }
    }
    
    /**
     * Constructs a new KeycloakOAuth2Client with a fresh ObjectMapper.
     */
    public KeycloakOAuth2Client() {
        this.objectMapper = new ObjectMapper();
    }

    /**
     * Validates user credentials by obtaining an access token from Keycloak.
     * 
     * <p>Uses the OAuth2 Resource Owner Password Credentials (ROPC) grant type
     * to exchange username/password for access and refresh tokens.</p>
     * 
     * @param username The username to authenticate
     * @param password The password to authenticate
     * @return true if credentials are valid and tokens were obtained
     * @throws IOException If the authentication request fails
     */
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
                // Calculate token expiration time
                int expiresIn = jsonNode.has("expires_in") ? jsonNode.get("expires_in").asInt() : 300; // Default 5 min
                this.tokenExpirationTime = System.currentTimeMillis() + (expiresIn * 1000L);
                // Calculate refresh token expiration time
                int refreshExpiresIn = jsonNode.has("refresh_expires_in") ? 
                    jsonNode.get("refresh_expires_in").asInt() : (int)(REFRESH_TOKEN_DEFAULT_EXPIRY_MS / 1000);
                this.refreshTokenExpirationTime = System.currentTimeMillis() + (refreshExpiresIn * 1000L);
                logger.info("Token will expire in " + expiresIn + " seconds, refresh token in " + refreshExpiresIn + " seconds");
                return true;
            } else {
                logger.info("Error: " + response.code() + " - " + response.body().string());
                return false;
            }
        }
    /**
     * Disconnects by logging out from Keycloak and invalidating tokens.
     * 
     * <p>Sends a logout request to Keycloak's logout endpoint and clears
     * all local token state. Also cleans up OkHttp connection pool resources.</p>
     * 
     * @return true if logout succeeds or no active session
     * @throws IOException If the logout request fails
     */
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
