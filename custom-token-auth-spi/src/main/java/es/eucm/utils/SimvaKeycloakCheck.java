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
    private boolean isSQLVersion;
    public SimvaKeycloakCheck() {
        try {
            simvaAdminClient.authenticate();
        } catch(IOException e) {
            logger.info(e.toString());
        }
    }

    public SimpleEntry<Boolean, String> checkTokenWithLoginHint(String username, String login_hint) throws IOException {
        if (login_hint == null || login_hint.isEmpty()) {
            logger.info("Login hint is empty");
            return new SimpleEntry<>(false, null);
        }

        String[] parts = login_hint.split(":");
        logger.info("Login hint parts: " + parts.length + ", values: " + String.join(", ", parts));
        SimpleEntry<Boolean, String> validate;

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
                logger.info("Login hint has more than one part, using first part as study: " + login_hint);
                validate = new SimpleEntry<>(false, null);
                break;
        }

        return validate;
    }

    public Boolean checkUsernamePassword(String username, String password) throws IOException {
        if(simvaUserClient.authenticate(username, password)) {
            logger.info("Validated user credentials");
            simvaUserClient.disconnect();
            return true;
        } else {
            logger.info("Invalidated user credentials");
            return false;
        }
    }

    public Boolean checkStudyScheduler(String study, String session, String activity) throws IOException {
        
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
                    return true;
                } else {
                    if(this.isSQLVersion && schedulerInfo.containsKey("activities")) {
                        Map<String, Object> scheduledActivity = getScheduledActivity(schedulerInfo.get("activities"), next);
                        logger.info("Activity: " + scheduledActivity);
                        Map<String, Object> completion = simvaUserClient.sendGetRequest("/activities/" + activity + "/completion");
                        logger.info("Completion: " + completion);
                        Boolean isCompleted = getCompletionValue(completion);
                        if(Boolean.TRUE.equals(isCompleted)
                                && scheduledActivity != null
                                && Boolean.TRUE.equals(scheduledActivity.get("activity_can_be_restarted"))) {
                            logger.info("Validated activity scheduler based on activities list");
                            return true;
                        }
                    }
                    logger.info("Invalidated activity scheduler");
                    return false;
                }
            } else {
                logger.info("Invalidated study scheduler");
                return false;
            }
        } else {
            logger.info("No scheduler info found for study: " + study);
            return false;
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
                this.isSQLVersion = simvaAdminClient.checkSQLVersion();
                if (this.isSQLVersion) {
                    authResult = handleSQLVersionTokenCheck(study, token);
                } else {
                    authResult=handleNoSQLVersionTokenCheck(study, token);
                }
            }
        }
        if(Boolean.TRUE.equals(authResult.getKey())) {
            this.simvaUserClient.disconnect();
            logger.info("Validated token in study");
            return authResult;
        } else {
            logger.info("Invalidated token in study");
            return new SimpleEntry<>(false, null);
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
                this.isSQLVersion = simvaAdminClient.checkSQLVersion();
                if (this.isSQLVersion) {
                    authResult = handleSQLVersionTokenCheck(study, token);
                } else {
                    authResult = handleNoSQLVersionTokenCheck(study, token);
                }
            }
        }
        if(Boolean.TRUE.equals(authResult.getKey())) {
            logger.info("Validated token in study, now checking scheduler");
            Boolean schedulerValid = checkStudyScheduler(study, session, activity);
            simvaUserClient.disconnect();
            if(schedulerValid) {
                logger.info("Validated study scheduler");
                return new SimpleEntry<>(true, authResult.getValue());
            } else {
                logger.info("Invalidated study scheduler");
                return new SimpleEntry<>(false, null);
            }
        } else {
            logger.info("Invalidated token in study");
            return new SimpleEntry<>(false, null);
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