package es.eucm.utils;

import es.eucm.utils.SimvaApiClient;
import es.eucm.utils.KeycloakOAuth2Client;
    import java.util.AbstractMap.SimpleEntry;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import org.jboss.logging.Logger;

public class SimvaKeycloakCheck {
    private static final Logger logger = Logger.getLogger(SimvaKeycloakCheck.class);

    private static SimvaApiClient simvaAdminClient = new SimvaApiClient();
    private static SimvaApiClient simvaUserClient = new SimvaApiClient();
    private static KeycloakOAuth2Client keycloakClient = new KeycloakOAuth2Client();
    private Boolean isSQLVersion = null;
    
    public SimvaKeycloakCheck() {
        try {
            // Use ensureAdminAuthenticated to avoid re-authenticating if token is still valid
            simvaAdminClient.ensureAdminAuthenticated();
            // Always determine SQL version first
            if (this.isSQLVersion == null) {
                this.isSQLVersion = simvaAdminClient.checkSQLVersion();
                logger.info("Determined SIMVA API version: " + (this.isSQLVersion ? "SQL" : "NoSQL"));
            }
        } catch(IOException e) {
            logger.info(e.toString());
        }
    }

    /**
     * Check token with login hint. If user is already authenticated in Keycloak,
     * verify they have access to the specific scheduler based on login_hint.
     * 
     * @param username The username (token or authenticated user's username)
     * @param login_hint The login hint containing study[:session:activity]
     * @param isAuthenticated Whether the user is already authenticated in Keycloak
     * @return SimpleEntry with (success, username)
     */
    public SimpleEntry<Boolean, String> checkTokenWithLoginHint(String username, String login_hint, boolean isAuthenticated) throws IOException {
        if (login_hint == null || login_hint.isEmpty()) {
            logger.info("Login hint is empty");
            // If user is authenticated but no login_hint, allow access
            if (isAuthenticated && username != null && !username.isEmpty()) {
                logger.info("User already authenticated, no login_hint required");
                return new SimpleEntry<>(true, username);
            }
            return new SimpleEntry<>(false, null);
        }

        String[] parts = login_hint.split(":");
        logger.info("Login hint parts: " + parts.length + ", values: " + String.join(", ", parts));
        SimpleEntry<Boolean, String> validate;

        // If user is already authenticated in Keycloak, check scheduler access directly
        if (isAuthenticated && username != null && !username.isEmpty()) {
            logger.info("User already authenticated in Keycloak, checking scheduler access for: " + username);
            validate = checkAuthenticatedUserSchedulerAccess(username, parts);
        } else {
            // User not authenticated, use token-based authentication
            switch(parts.length) {
                case 1:
                    logger.info("Login hint: " + login_hint);
                    validate = this.checkTokenInStudy(login_hint, username);
                    break;
                case 3:
                    logger.info("Login hint has three parts, using first part as study: " + login_hint);
                    validate = this.checkTokenInStudyAndActivity(parts[0], parts[1], parts[2], username);
                    break;
                default:
                    logger.info("Login hint has more than one part, not recognized: " + login_hint);
                    validate = new SimpleEntry<>(false, null);
                    break;
            }
        }

        return validate;
    }

    /**
     * Check scheduler access for an already authenticated user.
     * 
     * @param username The authenticated user's username
     * @param loginHintParts The parsed login_hint parts [study] or [study, session, activity]
     * @return SimpleEntry with (success, username)
     */
    private SimpleEntry<Boolean, String> checkAuthenticatedUserSchedulerAccess(String username, String[] loginHintParts) throws IOException {
        // Authenticate with user's credentials to access SIMVA API
        // For authenticated users, try to authenticate using their username
        if (!simvaUserClient.authenticateAsUser(username)) {
            logger.info("Failed to authenticate as user: " + username + ", falling back to admin client");
            // Try using admin client to verify user's scheduler access
            return new SimpleEntry<>(false, Messages.INVALID_TOKEN);
            //checkSchedulerAccessViaAdmin(username, loginHintParts);
        }

        try {
            this.isSQLVersion = simvaAdminClient.checkSQLVersion();
            
            String study = loginHintParts[0];
            
            if (loginHintParts.length == 1) {
                // Only study provided, check if user has access to study
                logger.info("Checking study access for authenticated user: " + username);
                SimpleEntry<Boolean, String> accessResult = checkUserStudyAccessWithError(study);
                simvaUserClient.disconnect();
                if (accessResult.getKey()) {
                    return new SimpleEntry<>(true, username);
                } else {
                    return new SimpleEntry<>(false, accessResult.getValue());
                }
            } else if (loginHintParts.length == 3) {
                // Study, session, activity provided, check scheduler
                String session = loginHintParts[1];
                String activity = loginHintParts[2];
                logger.info("Checking scheduler access for authenticated user: " + username);
                SimpleEntry<Boolean, String> schedulerResult = checkStudySchedulerWithError(study, session, activity);
                simvaUserClient.disconnect();
                if (schedulerResult.getKey()) {
                    logger.info("Authenticated user has valid scheduler access");
                    return new SimpleEntry<>(true, username);
                } else {
                    logger.info("Authenticated user does not have valid scheduler access: " + schedulerResult.getValue());
                    return new SimpleEntry<>(false, schedulerResult.getValue());
                }
            }
        } catch (IOException e) {
            logger.info("Error checking scheduler access: " + e.toString());
            simvaUserClient.disconnect();
        }
        
        return new SimpleEntry<>(false, null);
    }

    /**
     * Check scheduler access using admin client when user client auth fails.
     */
    private SimpleEntry<Boolean, String> checkSchedulerAccessViaAdmin(String username, String[] loginHintParts) throws IOException {
        this.isSQLVersion = simvaAdminClient.checkSQLVersion();
        String study = loginHintParts[0];
        
        // Check if user is a participant in the study
        Boolean isParticipant = checkUserIsParticipantInStudy(username, study);
        if (!isParticipant) {
            logger.info("User is not a participant in study: " + study);
            return new SimpleEntry<>(false, null);
        }
        
        logger.info("User is a participant in study, granting access");
        return new SimpleEntry<>(true, username);
    }

    /**
     * Check if user has access to the study's schedule.
     * @return SimpleEntry with (success, errorMessage) - errorMessage is null on success
     */
    private SimpleEntry<Boolean, String> checkUserStudyAccessWithError(String study) throws IOException {
        Map<String, Object> schedulerInfo;
        if (this.isSQLVersion) {
            schedulerInfo = simvaUserClient.sendGetRequest("/simlets/" + study + "/schedule");
        } else {
            schedulerInfo = simvaUserClient.sendGetRequest("/studies/" + study + "/schedule");
        }
        
        if (schedulerInfo != null) {
            // Check for ValidationError (e.g., session not active yet)
            Object typeObj = schedulerInfo.get("type");
            Object messageObj = schedulerInfo.get("message");
            if (typeObj != null && "ValidationError".equals(typeObj.toString())) {
                String message = messageObj != null ? messageObj.toString() : "";
                if (message.contains("active")) {
                    logger.info("Session is not active yet: " + message);
                    return new SimpleEntry<>(false, Messages.SESSION_NOT_ACTIVE);
                }
                logger.info("Validation error: " + message);
                return new SimpleEntry<>(false, Messages.NO_SCHEDULER_INFO);
            }
            
            // Check for valid scheduler response
            if ((schedulerInfo.containsKey("study") || schedulerInfo.containsKey("simlet")) 
                    && schedulerInfo.containsKey("next")) {
                return new SimpleEntry<>(true, null);
            }
        }
        
        return new SimpleEntry<>(false, Messages.USER_NOT_PARTICIPANT);
    }

    /**
     * Check if a user is a participant in the given study.
     */
    private Boolean checkUserIsParticipantInStudy(String username, String study) {
        try {
            String requestUrl;
            if (this.isSQLVersion) {
                requestUrl = "/simlets/" + study + "/groups";
            } else {
                requestUrl = "/studies/" + study + "/groups";
            }
            
            Map<String, Object> groups = simvaAdminClient.sendGetRequest(requestUrl);
            for (Object groupObj : groups.values()) {
                if (!(groupObj instanceof Map)) {
                    continue;
                }
                
                Map<String, Object> group = (Map<String, Object>) groupObj;
                String groupId = getGroupID(group);
                
                String participantsUrl;
                if (this.isSQLVersion) {
                    participantsUrl = "/simlets/" + study + "/groups/" + groupId + "/participants";
                } else {
                    participantsUrl = "/studies/" + study + "/groups/" + groupId + "/participants";
                }
                
                Map<String, Object> participants = simvaAdminClient.sendGetRequest(participantsUrl);
                for (Object participantObj : participants.values()) {
                    if (!(participantObj instanceof Map)) {
                        continue;
                    }
                    
                    Map<String, Object> participant = (Map<String, Object>) participantObj;
                    String participantUsername = participant.get("username") != null ? 
                        participant.get("username").toString() : null;
                    
                    if (username.equals(participantUsername)) {
                        logger.info("Found user " + username + " as participant in group " + groupId);
                        return true;
                    }
                }
            }
        } catch (IOException e) {
            logger.info("Error checking participant status: " + e.toString());
        }
        return false;
    }

    public SimpleEntry<Boolean, String> checkUsernamePassword(String username, String password) throws IOException {
        if(simvaUserClient.authenticate(username, password)) {
            logger.info("Validated user credentials");
            return checkUserAccessNotATokenForAuthenticatedUser(username);
        } else {
            logger.info("Invalidated user credentials");
            return new SimpleEntry<>(false, Messages.INVALID_USERNAME_OR_PASSWORD);
        }
    }

    public SimpleEntry<Boolean, String> checkUserAccessNotATokenForAuthenticatedUser(String username) throws IOException {
        // Check if user is a token user, if so invalidate credentials since they must use token authentication
        // Use simvaUserClient (already authenticated as this user) to get /users/me
        Map<String, Object> userInfo = simvaUserClient.sendGetRequest("/users/me");
        logger.info("User info response for /users/me: " + userInfo);
        if(userInfo != null && userInfo.get("isToken") != null) {
            Object isTokenValue = userInfo.get("isToken");
            boolean isToken = Boolean.TRUE.equals(isTokenValue)
                || (isTokenValue instanceof String && Boolean.parseBoolean((String) isTokenValue));
            if (isToken) {
                logger.info("Token users cannot access if not via token authentication, invalidating credentials");
                simvaUserClient.disconnect();
                return new SimpleEntry<>(false, Messages.TOKEN_USER_MUST_USE_TOKEN_AUTHENTIFICATION);
            }
        }
        String retrievedUsername = userInfo != null && userInfo.get("username") != null 
            ? userInfo.get("username").toString() 
            : username;
        logger.info("Retrieved user info for username: " + retrievedUsername);
        simvaUserClient.disconnect();
        return new SimpleEntry<>(true, retrievedUsername);
    }

    /**
     * Check study scheduler and return error message on failure.
     * @return SimpleEntry with (success, errorMessage) - errorMessage is null on success
     */
    public SimpleEntry<Boolean, String> checkStudySchedulerWithError(String study, String session, String activity) throws IOException {
        Map<String, Object> schedulerInfo;
        if(this.isSQLVersion) {
            schedulerInfo = simvaUserClient.sendGetRequest("/simlets/" + study + "/schedule");
        } else {
            schedulerInfo = simvaUserClient.sendGetRequest("/studies/" + study + "/schedule");
        }
        if(schedulerInfo != null) {
            logger.info("Scheduler info: " + schedulerInfo);
            Object schedulerStudyObj;
            Object schedulerSessionObj;
            if(this.isSQLVersion) {
                schedulerStudyObj = schedulerInfo.get("simlet");
                schedulerSessionObj = schedulerInfo.get("session");
            } else {
                schedulerStudyObj = schedulerInfo.get("study");
                schedulerSessionObj = schedulerInfo.get("test");
            }
            String schedulerStudy = schedulerStudyObj == null ? null : schedulerStudyObj.toString();
            String schedulerSession = schedulerSessionObj == null ? null : schedulerSessionObj.toString();
            Object nextObj = schedulerInfo.get("next");
            String next = nextObj == null ? null : nextObj.toString();

            if(schedulerSession != null && schedulerStudy != null
                    && schedulerSession.equals(session) && schedulerStudy.equals(study)) {
                if(next != null && next.equals(activity)) {
                    logger.info("Validated activity scheduler");
                    return new SimpleEntry<>(true, null);
                } else {
                    if(this.isSQLVersion && schedulerInfo.containsKey("activities")) {
                        Map<String, Object> scheduledActivity = getScheduledActivity(schedulerInfo.get("activities"), next);
                        logger.info("Activity: " + scheduledActivity);
                        Map<String, Object> completion = simvaUserClient.sendGetRequest("/activities/" + activity + "/completion");
                        logger.info("Completion: " + completion);
                        Boolean isCompleted = getCompletionValue(completion);
                        if(Boolean.TRUE.equals(isCompleted)) {
                            if(scheduledActivity != null
                                    && Boolean.TRUE.equals(scheduledActivity.get("activity_can_be_restarted"))) {
                                logger.info("Validated activity scheduler based on activities list");
                                return new SimpleEntry<>(true, null);
                            } else {
                                logger.info("Activity cannot be restarted");
                                return new SimpleEntry<>(false, Messages.ACTIVITY_CANNOT_BE_RESTARTED);
                            }
                        }
                    }
                    logger.info("Not the current activity");
                    return new SimpleEntry<>(false, Messages.NOT_CURRENT_ACTIVITY);
                }
            } else {
                logger.info("Invalidated study scheduler");
                return new SimpleEntry<>(false, Messages.INVALID_SCHEDULER);
            }
        } else {
            logger.info("No scheduler info found for study: " + study);
            return new SimpleEntry<>(false, Messages.NO_SCHEDULER_INFO);
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> getScheduledActivity(Object activitiesObj, String next) {
        if (activitiesObj == null || next == null) {
            return null;
        }

        if (activitiesObj instanceof Map) {
            Object scheduled = ((Map<?, ?>) activitiesObj).get(next);
            if (scheduled instanceof Map) {
                return (Map<String, Object>) scheduled;
            }
            return null;
        }

        if (activitiesObj instanceof List) {
            try {
                int idx = Integer.parseInt(next);
                List<?> activities = (List<?>) activitiesObj;
                if (idx >= 0 && idx < activities.size() && activities.get(idx) instanceof Map) {
                    return (Map<String, Object>) activities.get(idx);
                }
            } catch (NumberFormatException ignored) {
                return null;
            }
        }

        return null;
    }

    private Boolean getCompletionValue(Map<String, Object> completion) {
        if (completion == null) {
            return false;
        }

        Object completed = completion.get("value");
        if (completed == null) {
            completed = completion.get("completed");
        }
        if (completed instanceof Boolean) {
            return (Boolean) completed;
        }
        if (completed instanceof String) {
            return Boolean.parseBoolean((String) completed);
        }

        return false;
    }

    public SimpleEntry<Boolean, String> checkTokenInStudy(String study, String token) throws IOException {
        SimpleEntry<Boolean, String> authResult = new SimpleEntry<>(false, null);
        // Try direct token authentication first
        Boolean directAuthResult = tryDirectTokenAuth(token);
        if (Boolean.TRUE.equals(directAuthResult)) {
            authResult = new SimpleEntry<>(directAuthResult, token);
        }

        // Token auth failed - need to look up user in study
        if(authResult == null || !authResult.getKey()) {
            if (study == null) {
                authResult = new SimpleEntry<>(false, null);
            } else{
                if (this.isSQLVersion) {
                    authResult = handleSQLVersionTokenCheck(study, token);
                } else {
                    authResult=handleNoSQLVersionTokenCheck(study, token);
                }
            }
        }
        if(Boolean.TRUE.equals(authResult.getKey())) {
            SimpleEntry<Boolean, String> schedulerResult = this.checkUserStudyAccessWithError(study);
            this.simvaUserClient.disconnect();
            if(schedulerResult.getKey()) {
                logger.info("Validated token in study");
                return new SimpleEntry<>(true, authResult.getValue());
            } else {
                logger.info("User study access check failed: " + schedulerResult.getValue());
                return new SimpleEntry<>(false, schedulerResult.getValue());
            }
        } else {
            logger.info("Invalidated token in study");
            return new SimpleEntry<>(false, Messages.INVALID_TOKEN);
        }
    }

    public SimpleEntry<Boolean, String> checkTokenInStudyAndActivity(String study, String session, String activity, String token) throws IOException {
        SimpleEntry<Boolean, String> authResult = new SimpleEntry<>(false, null);
        // Try direct token authentication first
        Boolean directAuthResult = tryDirectTokenAuth(token);
        if (Boolean.TRUE.equals(directAuthResult)) {
            authResult = new SimpleEntry<>(directAuthResult, token);
        }

        // Token auth failed - need to look up user in study
        if (authResult == null || !authResult.getKey()) {
            if(study == null) {
                authResult = new SimpleEntry<>(false, null);
            } else{
                if (this.isSQLVersion) {
                    authResult = handleSQLVersionTokenCheck(study, token);
                } else {
                    authResult = handleNoSQLVersionTokenCheck(study, token);
                }
            }
        }
        if(Boolean.TRUE.equals(authResult.getKey())) {
            logger.info("Validated token in study, now checking scheduler");
            SimpleEntry<Boolean, String> schedulerResult = checkStudySchedulerWithError(study, session, activity);
            simvaUserClient.disconnect();
            if(schedulerResult.getKey()) {
                logger.info("Validated study scheduler");
                return new SimpleEntry<>(true, authResult.getValue());
            } else {
                logger.info("Invalidated study scheduler: " + schedulerResult.getValue());
                return new SimpleEntry<>(false, schedulerResult.getValue());
            }
        } else {
            logger.info("Invalidated token in study");
            return new SimpleEntry<>(false, Messages.INVALID_TOKEN);
        }
    }

    private Boolean tryDirectTokenAuth(String token) throws IOException {
        if (simvaUserClient.authenticate(token, token)) {
            logger.info("Validated token");
            return true;
        } else {
            logger.info("Invalidated token");
            return false;
        }
    }

    private SimpleEntry<Boolean, String> handleSQLVersionTokenCheck(String study, String token) {
        logger.info("Using SQL version of SIMVA API");
        
        // Try study_token username format first
        String studyTokenUsername = study + "_" + token;
        Boolean result = tryAuthenticateWithUsername(studyTokenUsername, token);
        if (Boolean.TRUE.equals(result)) {
            return new SimpleEntry<>(result, studyTokenUsername);
        }

        // Search through groups and participants
        return searchParticipantsForToken(study, token);
    }

    private SimpleEntry<Boolean, String> searchParticipantsForToken(String study, String token) {
        try {
            
            String requestUrl;
            if(this.isSQLVersion) {
                requestUrl = "/simlets/" + study + "/groups";
            } else {
                requestUrl = "/studies/" + study + "/groups";
            }
            logger.info("Request URL: " + requestUrl);
            Map<String, Object> groups = simvaAdminClient.sendGetRequest(requestUrl);
            for (Object groupObj : groups.values()) {
                if (!(groupObj instanceof Map)) {
                    continue;
                }
                
                Map<String, Object> group = (Map<String, Object>) groupObj;
                String groupId = getGroupID(group);
                logger.info("Group : " + groupId);
                
                SimpleEntry<Boolean, String> result = searchGroupParticipantsForToken(study, groupId, token);
                if (Boolean.TRUE.equals(result.getKey())) {
                    return result;
                }
            }
        } catch (IOException e) {
            logger.info(e.toString());
        }
        return new SimpleEntry<>(false, null);
    }

    private SimpleEntry<Boolean, String> searchGroupParticipantsForToken(String study, String groupId, String token) {
        try {
            String requestUrl;
            if(this.isSQLVersion) {
                requestUrl = "/simlets/" + study + "/groups/" + groupId + "/participants";
            } else {
                requestUrl = "/studies/" + study + "/groups/" + groupId + "/participants";
            }
            logger.info("Request URL: " + requestUrl);
            Map<String, Object> participants = simvaAdminClient.sendGetRequest(requestUrl);
            logger.info("Participants : " + participants);
            for (Object participantObj : participants.values()) {
                if (!(participantObj instanceof Map)) {
                    logger.warn("Unexpected participant type: " + participantObj.getClass().getName());
                    continue;
                }
                
                Map<String, Object> participant = (Map<String, Object>) participantObj;
                logger.info(participant);
                if (isMatchingTokenParticipant(participant, token)) {
                    String updatedUsername = participant.get("username").toString();
                    Boolean result = tryAuthenticateWithUsername(updatedUsername, token);
                    if (Boolean.TRUE.equals(result)) {
                        return new SimpleEntry<>(result, updatedUsername);
                    }
                }
            }
        } catch (IOException e) {
            logger.info(e.toString());
        }
        return new SimpleEntry<>(false, null);
    }

    private Boolean isMatchingTokenParticipant(Map<String, Object> participant, String token) {
        if (token == null || token.isEmpty()) {
            return false;
        }

        Object isTokenValue = participant.get("isToken");
        boolean isToken = Boolean.TRUE.equals(isTokenValue)
            || (isTokenValue instanceof String && Boolean.parseBoolean((String) isTokenValue));

        Object participantTokenValue = participant.get("token");
        if (!isToken || participantTokenValue == null) {
            return false;
        }

        String participantToken = participantTokenValue.toString();
        return !participantToken.isEmpty() && participantToken.equals(token);
    }

    private SimpleEntry<Boolean, String> handleNoSQLVersionTokenCheck(String study, String token) {
        logger.info("Using NoSQL version of SIMVA API");
        
        try {
            Map<String, Object> groups = simvaAdminClient.sendGetRequest("/studies/" + study + "/groups");
            for (Object groupObj : groups.values()) {
                if (!(groupObj instanceof Map)) {
                    logger.warn("Unexpected group type: " + groupObj.getClass().getName());
                    continue;
                }
                
                Map<String, Object> group = (Map<String, Object>) groupObj;
                String groupId = group.get("_id").toString();
                logger.info("Group : " + groupId);
                logger.info("Participants : " + group.get("participants"));
                String updatedUsername = groupId + "_" + token;
                Boolean result = tryAuthenticateWithUsername(updatedUsername, token);
                if (Boolean.TRUE.equals(result)) {
                     return new SimpleEntry<>(result, updatedUsername);
                }
            }
        } catch (IOException e) {
            logger.info(e.toString());
        }
        return new SimpleEntry<>(false, null);
    }

    private Boolean tryAuthenticateWithUsername(String username, String token) {
        try {
            if (simvaUserClient.authenticate(username, token)) {
                logger.info("Validated token for : " + username);
                return true;
            }
        } catch (IOException e) {
            logger.info(e.toString());
        }
        return false;
    }

    private String getGroupID(Map<String, Object> group) {
        // Try SQL version field first, then NoSQL version
        if(this.isSQLVersion) {
            if (group.containsKey("group_id")) {
                return group.get("group_id").toString();
            }
        } else {
             if (group.containsKey("_id")) {
                return group.get("_id").toString();
            }
        }
        return null;
    }
}