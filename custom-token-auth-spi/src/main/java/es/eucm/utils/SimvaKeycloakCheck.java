package es.eucm.utils;

import es.eucm.utils.SimvaApiClient;
import es.eucm.utils.KeycloakOAuth2Client;
import java.util.AbstractMap.SimpleEntry;

import java.io.IOException;
import java.util.Map;

import org.jboss.logging.Logger;

public class SimvaKeycloakCheck {
    private static final Logger logger = Logger.getLogger(SimvaKeycloakCheck.class);

    private static SimvaApiClient simvaClient = new SimvaApiClient();  // Initialize client from environment variables
    private static KeycloakOAuth2Client keycloakClient = new KeycloakOAuth2Client();

    public SimvaKeycloakCheck() {
        try {
            simvaClient.authenticate();
        } catch(IOException e) {
            logger.info(e.toString());
        }
    }

    public Boolean checkUsernamePassword(String username, String password) throws IOException {
        if(keycloakClient.validateUserCredentials(username, password)) {
            logger.info("Validated user credentials");
            keycloakClient.disconnect();
            return true;
        } else {
            logger.info("Invalidated user credentials");
            return false;
        }
    }

    public SimpleEntry<Boolean, String> checkTokenInStudy(String study, String token) throws IOException {
        if(keycloakClient.validateUserCredentials(token, token)) {
            logger.info("Validated token");
            keycloakClient.disconnect();
            return new SimpleEntry<>(true, token);
        } else {
            logger.info("Invalidated token");
            if(study == null) {
                return new SimpleEntry<>(false, null);
            } else {
                Map<String, Object> groups = simvaClient.sendGetRequest("/studies/" + study + "/groups");
                for(Object groupObj : groups.values()) {
                    // Check if groupObj is indeed a Map
                    if (groupObj instanceof Map) {
                        Map<String, Object> group = (Map<String, Object>) groupObj;
                        logger.info("Group : " + group.get("_id"));
                        logger.info("Participants : " + group.get("participants"));
                        try {
                            // Create a new username based on your logic
                            String updatedUsername = group.get("_id") + "_" + token;
                            if(keycloakClient.validateUserCredentials(updatedUsername, token)) {
                                logger.info("Validated token for : " + updatedUsername);
                                keycloakClient.disconnect();
                                return new SimpleEntry<>(true, updatedUsername);
                            }
                        } catch(IOException e){
                            logger.info(e.toString());
                        }
                    } else {
                        logger.warn("Unexpected group type: " + groupObj.getClass().getName());
                    }
                }
                return new SimpleEntry<>(false, null);
            }
        }
    }
}
