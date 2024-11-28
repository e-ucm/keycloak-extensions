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

    private static SimvaApiConfig apiConfig = new SimvaApiConfig();
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

    public void authenticate() throws IOException {
        // Create an ObjectMapper instance
        ObjectMapper objectMapper = new ObjectMapper();
        // Create a JSON object using ObjectNode
        ObjectNode payload = objectMapper.createObjectNode();
        payload.put("username", apiConfig.getAdminUsername());
        payload.put("password", apiConfig.getAdminPassword());
        // Convert the JSON object to a string
        String jsonPayload = objectMapper.writeValueAsString(payload);
        // Define the API URL
        String apiUrl = "/users/login";
        // Read the body of the response into a hashmap
        Map<String,Object> responseMap = this.sendPostRequest(apiUrl, jsonPayload);
        // Read the value of the "access_token" key from the hashmap 
        this.bearerToken = "Bearer " + (String)responseMap.get("token");
        logger.info("Token: " + this.bearerToken);
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
}