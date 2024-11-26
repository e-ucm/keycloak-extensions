package es.eucm.keycloak;

import es.eucm.utils.SimvaApiClient;
import es.eucm.utils.KeycloakOAuth2Client;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.authentication.Authenticator;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.services.managers.AuthenticationManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.io.IOException;
import java.util.Map;

public class CustomAuthenticator extends AbstractUsernameFormAuthenticator implements Authenticator {

    private final Logger logger = LoggerFactory.getLogger(CustomAuthenticator.class);

    private ObjectMapper objectMapper = new ObjectMapper();

    private final KeycloakSession session;
    private SimvaApiClient simvaClient;
    private KeycloakOAuth2Client keycloakClient;

    public CustomAuthenticator(KeycloakSession session) {
        this.session = session;
        this.simvaClient = new SimvaApiClient();  // Initialize client from environment variables
        try {
            if(!this.simvaClient.isAuthentificated()) {
                this.simvaClient.authenticate();
            }
        } catch(IOException e) {
            logger.info(e.toString());
        }
        this.keycloakClient = new KeycloakOAuth2Client();
    }

    /**
     * Method is used for user authentication. It authentificate via password and username or via token and that returns a jwt token if the user is authenticated
     * If the user is authenticated an authenticated user is set.
     * Whereas if the user is not authenticated, an error is set.
     * @param context
     */
    @Override
    public void authenticate(AuthenticationFlowContext context) {
        logMap(context.getHttpRequest().getUri().getQueryParameters());
        String tokenPresent = context.getHttpRequest().getUri().getQueryParameters().getFirst("token");
        
        MultivaluedMap<String, String> formData = new MultivaluedHashMap<>();
        String loginHint = context.getAuthenticationSession().getClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM);

        String rememberMeUsername = AuthenticationManager.getRememberMeUsername(context.getSession());
        if (context.getUser() != null) {
            LoginFormsProvider form = context.form();
            form.setAttribute(LoginFormsProvider.USERNAME_HIDDEN, true);
            form.setAttribute(LoginFormsProvider.REGISTRATION_DISABLED, true);
            context.getAuthenticationSession().setAuthNote(USER_SET_BEFORE_USERNAME_PASSWORD_AUTH, "true");
        } else {
            context.getAuthenticationSession().removeAuthNote(USER_SET_BEFORE_USERNAME_PASSWORD_AUTH);
            if (loginHint != null || rememberMeUsername != null) {
                if (loginHint != null) {
                    formData.add(AuthenticationManager.FORM_USERNAME, loginHint);
                } else {
                    formData.add(AuthenticationManager.FORM_USERNAME, rememberMeUsername);
                    formData.add("rememberMe", "on");
                }
            }
        }

        if(tokenPresent == null) {
            logger.info("AUTHENTICATE username/password custom provider");
            Response challengeResponse = challenge(context.form(), formData);
            context.challenge(challengeResponse);
        } else {
            StringBuilder studyurl = new StringBuilder();
            studyurl.append("");
            String study = context.getHttpRequest().getUri().getQueryParameters().getFirst("state");
            if(study != "") {
                studyurl.append("&state=").append(study);
            }
            logger.info("AUTHENTICATE token custom provider");
            Response challengeResponse = challenge(context.form().setAttribute("studyurl", studyurl.toString()), formData);
            context.challenge(challengeResponse);
        }
    }

    protected Response challenge(LoginFormsProvider forms, MultivaluedMap<String, String> formData) {
        if (formData.size() > 0) forms.setFormData(formData);

        return forms.createLoginUsernamePassword();
    }

    public void logMap(MultivaluedMap<String, String> formData) {
        StringBuilder logMessage = new StringBuilder();

        // Iterate over each entry and append to the log message
        for (String key : formData.keySet()) {
            // For each key, get all values associated with it (since it's MultivaluedMap)
            for (String value : formData.get(key)) {
                logMessage.append(key).append("=").append(value).append(", ");
            }
        }

        // Remove the trailing comma and space if present
        if (logMessage.length() > 0) {
            logMessage.setLength(logMessage.length() - 2); // Remove last ", "
        }

        // Log the message
        logger.info("Data: {}", logMessage.toString());
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        logMap(context.getHttpRequest().getUri().getQueryParameters());
        logger.info("CUSTOMER PROVIDER action");
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        logMap(formData);
        if (formData.containsKey("cancel")) {
            context.cancelLogin();
            return;
        }
        String username = formData.getFirst("username");
        String password = formData.getFirst("password");
        try {
            if(this.keycloakClient.validateUserCredentials(username, password)) {
                logger.info("Validated user credentials");
            } else {
                logger.info("Invalidated user credentials");
            }
        } catch(IOException e){
            logger.info(e.toString());
        }
        String tokenPresent = context.getHttpRequest().getUri().getQueryParameters().getFirst("token");
        logger.info("token Present : " + tokenPresent);
        if(tokenPresent != null) {
            String study = context.getHttpRequest().getUri().getQueryParameters().getFirst("state");
            try {
                Map<String, Object> groups = this.simvaClient.sendGetRequest("/studies/" + study + "/groups");
                for(Object groupObj : groups.values()) {
                        // Check if groupObj is indeed a Map
                        if (groupObj instanceof Map) {
                            Map<String, Object> group = (Map<String, Object>) groupObj;
                            logger.info("Group : " + group.get("_id"));
                            logger.info("Participants : " + group.get("participants"));
                            try {
                                // Create a new username based on your logic
                                String updatedUsername = group.get("_id") + "_" + username;
                                if(this.keycloakClient.validateUserCredentials(updatedUsername, password)) {
                                    // Set the new username in the authentication session
                                    context.setUser(context.getSession().users().getUserByUsername(context.getRealm(), updatedUsername));
                                    logger.info(context.getSession().users().toString());
                                    context.success(); // Proceed if token is valid
                                    return;
                                }
                            } catch(IOException e){
                                logger.info(e.toString());
                            }
                        } else {
                            logger.warn("Unexpected group type: " + groupObj.getClass().getName());
                        }
                }
            } catch(IOException e) {
                logger.info(e.toString());
            }
            //Check in keycloak / SIMVA API username is in one of the study groups
            //TODO log in to SIMVA API
            logger.info("AUTHENTICATE token custom provider: " + username);
            if(!validateForm(context, formData)) {
                StringBuilder studyurl = new StringBuilder();
                studyurl.append("");
                if(study != "") {
                    studyurl.append("&state=").append(study);
                }
                // Create a form error response
                Response challengeResponse = context.form()
                    .setError("Missing or invalid token.")
                    .setAttribute("token", "true")
                    .setAttribute("studyurl", studyurl.toString())
                    .createForm("login.ftl");
                context.challenge(challengeResponse);
            } else {
                context.success(); // Proceed if token is valid
            }
        } else {
            logger.info("AUTHENTICATE username password custom provider: " + username);
            if(!validateForm(context, formData))  {
                // Create a form error response
                Response challengeResponse = context.form()
                    .setError("Missing or invalid username or password.")
                    .createForm("login.ftl");
                context.challenge(challengeResponse);
            } else {
                context.success(); // Proceed if token is valid
            }
        }
    }

    protected boolean validateForm(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        return validateUserAndPassword(context, formData);
    }
    
    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // Set the required actions for the user after authentication
    }

    @Override
    public void close() {
        // Closes any open resources
    }
}
