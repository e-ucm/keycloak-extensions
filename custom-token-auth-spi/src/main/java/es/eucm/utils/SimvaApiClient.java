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

public class SimvaApiClient {
    private static final Logger logger = Logger.getLogger(SimvaApiClient.class);
    private static KeycloakOAuth2Client keycloakClient = new KeycloakOAuth2Client();

    private static SimvaApiConfig apiConfig = new SimvaApiConfig();
    private String username;
    private String password;
    private String bearerToken;
    private OkHttpClient client;

    public SimvaApiClient() {
        try {
            // Create a new HTTP client
            this.client = new OkHttpClient().newBuilder().build();
        } catch(Exception e) {
            logger.info(e.toString());
        }
    }

    public boolean isAuthentificated() {
        return this.bearerToken != null;
    }

    public boolean authenticate() throws IOException{
        return authenticate(apiConfig.getAdminUsername(), apiConfig.getAdminPassword());
    }

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

    public boolean disconnect() throws IOException {
        this.keycloakClient.disconnect();
        this.username = null;
        this.password = null;
        this.bearerToken = null;
        return true;
    }

    // Method to send GET request
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

    //// Method to send POST request with JSON body (if needed)
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