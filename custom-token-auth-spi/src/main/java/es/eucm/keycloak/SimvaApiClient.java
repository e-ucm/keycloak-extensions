package es.eucm.keycloak;

import es.eucm.keycloak.ApiConfig;

import org.jboss.logging.Logger;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Base64;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

public class SimvaApiClient {
    private static final Logger logger = Logger.getLogger(SimvaApiClient.class);

    private ApiConfig apiConfig;
    private String bearerToken;

    public SimvaApiClient() {
        this.apiConfig = new ApiConfig();
        this.apiConfig.printConfig();
    }

    public boolean isAuthentificated() {
        return this.bearerToken != null;
    }

    public void authenticate() throws Exception {
        // Create an ObjectMapper instance
        ObjectMapper objectMapper = new ObjectMapper();

        // Create a JSON object using ObjectNode
        ObjectNode payload = objectMapper.createObjectNode();
        payload.put("username", this.apiConfig.getAdminUsername());
        payload.put("password", this.apiConfig.getAdminPassword());

        // Convert the JSON object to a string
        String jsonPayload = objectMapper.writeValueAsString(payload);

        // Define the API URL
        String apiUrl = this.apiConfig.getApiUrl() + "/users/login";

        // Make the POST request
        HttpURLConnection connection = (HttpURLConnection) new URL(apiUrl).openConnection();
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type", "application/json");
        connection.setDoOutput(true);

        // Send the request body (JSON payload)
        try (OutputStream os = connection.getOutputStream()) {
            byte[] input = jsonPayload.getBytes("utf-8");
            os.write(input, 0, input.length);
        }

        // Get the response
        int responseCode = connection.getResponseCode();
        if (responseCode != HttpURLConnection.HTTP_OK) {
            throw new RuntimeException("Failed : HTTP error code : " + responseCode);
        }

        // Read the response
        BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        String inputLine;
        StringBuffer response = new StringBuffer();
        while ((inputLine = in.readLine()) != null) {
            response.append(inputLine);
        }
        in.close();

        // Parse the JSON response
        objectMapper = new ObjectMapper();
        JsonNode jsonNode = objectMapper.readTree(response.toString());

        // Access the token
        this.bearerToken = "Bearer " + jsonNode.get("token").asText();
        logger.info(this.bearerToken);
    }

    // Method to send GET request
    public JsonNode sendGetRequest(String concat_url) throws Exception {
        // Construct the URL
        String urlString = this.apiConfig.getApiUrl() + concat_url;
        logger.info("urlString: " + urlString);
        URL url = new URL(urlString);

        // Open connection
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");

        // Add Bearer Authentication header
        connection.setRequestProperty("Authorization", this.bearerToken);

        // Read the response
        int responseCode = connection.getResponseCode();
        logger.info("Response Code: " + responseCode);

        BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        String inputLine;
        StringBuffer response = new StringBuffer();
        while ((inputLine = in.readLine()) != null) {
            response.append(inputLine);
        }
        in.close();

        // Print the response
        logger.info("Response: " + response.toString());

        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode jsonNode = objectMapper.readTree(response.toString());
        return jsonNode;
    }

    // Method to send POST request with JSON body (if needed)
    public void sendPostRequest(String concat_url, String jsonBody) throws Exception {
        // Construct the URL
        String urlString = this.apiConfig.getApiUrl() + concat_url;
        logger.info("urlString: " + urlString);
        URL url = new URL(urlString);

        // Open connection
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setDoOutput(true);

        // Add Bearer Authentication header
        connection.setRequestProperty("Authorization", this.bearerToken);
        connection.setRequestProperty("Content-Type", "application/json");

        // Send the request body (JSON)
        try (OutputStream os = connection.getOutputStream()) {
            byte[] input = jsonBody.getBytes("utf-8");
            os.write(input, 0, input.length);
        }

        // Read the response
        int responseCode = connection.getResponseCode();
        logger.info("Response Code: " + responseCode);

        BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        String inputLine;
        StringBuffer response = new StringBuffer();
        while ((inputLine = in.readLine()) != null) {
            response.append(inputLine);
        }
        in.close();

        // Print the response
        logger.info("Response: " + response.toString());
    }
}
