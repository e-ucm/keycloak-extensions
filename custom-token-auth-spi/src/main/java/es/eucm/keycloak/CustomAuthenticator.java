package es.eucm.keycloak;

import es.eucm.utils.SimvaKeycloakCheck;
import es.eucm.utils.Messages;

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

import java.util.AbstractMap.SimpleEntry;

public class CustomAuthenticator extends AbstractUsernameFormAuthenticator implements Authenticator {

    private final Logger logger = LoggerFactory.getLogger(CustomAuthenticator.class);

    private ObjectMapper objectMapper = new ObjectMapper();

    private final KeycloakSession session;
    private SimvaKeycloakCheck simvaKeycloakCheck;

    public CustomAuthenticator(KeycloakSession session) {
        this.session = session;
        simvaKeycloakCheck= new SimvaKeycloakCheck();
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
        logMap(context.getHttpRequest().getDecodedFormParameters());
        String simvaUserTokenPresent = context.getHttpRequest().getUri().getQueryParameters().getFirst("simva_user_token");
        String hideLocaleDropdown = context.getHttpRequest().getUri().getQueryParameters().getFirst("hideLocaleDropdown");

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
        StringBuilder stringurl = new StringBuilder();
        stringurl.append("");
        if(hideLocaleDropdown != null) {
            stringurl.append("&hideLocaleDropdown=").append(hideLocaleDropdown);
        }
        if(simvaUserTokenPresent != null && simvaUserTokenPresent == "true") {
            String study = context.getHttpRequest().getUri().getQueryParameters().getFirst("login_hint");
            if(study != "") {
                stringurl.append("&login_hint=").append(study);
            }
            stringurl.append("&simva_user_token=true");
            logger.info(stringurl.toString());
            logger.info("AUTHENTICATE token custom provider");
            Response challengeResponse = challenge(context.form()
                .setAttribute("hideLocaleDropdown", hideLocaleDropdown)
                .setAttribute("stringurl", stringurl.toString())
                .setAttribute("simvaUserToken", "true")
                , formData
            );
            context.challenge(challengeResponse);
        } else {
            logger.info("AUTHENTICATE username/password custom provider");
            logger.info(stringurl.toString());
            Response challengeResponse = challenge(context.form()
               .setAttribute("hideLocaleDropdown", hideLocaleDropdown)
               .setAttribute("stringurl", stringurl.toString())
             , formData
           );
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
        logger.info("CUSTOMER PROVIDER action");
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        if(validateUserAndPassword(context, formData)) {
            context.success(); // Proceed if token is valid
        } else {
            logMap(context.getHttpRequest().getUri().getQueryParameters());
            logMap(formData);
            if (formData.containsKey("cancel")) {
                context.cancelLogin();
                return;
            }
            String errorMsg;
            String username = formData.getFirst("username");
            String password = formData.getFirst("password");
            String simvaUserTokenPresent = context.getHttpRequest().getUri().getQueryParameters().getFirst("simva_user_token");
            logger.info("Simva User Token Present : " + simvaUserTokenPresent);
            String hideLocaleDropdown = context.getHttpRequest().getUri().getQueryParameters().getFirst("hideLocaleDropdown");
            StringBuilder stringurl = new StringBuilder();
            stringurl.append("");
            if(hideLocaleDropdown != null) {
                stringurl.append("&hideLocaleDropdown=").append(hideLocaleDropdown);
            }
            if(simvaUserTokenPresent != null && simvaUserTokenPresent == "true") {
                if(username.isEmpty()) {
                    errorMsg=Messages.EMPTY_VALUE;
                } else {
                    errorMsg=Messages.INVALID_VALUE;
                }
                logger.info("AUTHENTICATE token custom provider: " + username);
                String study = context.getHttpRequest().getUri().getQueryParameters().getFirst("login_hint");
                logger.info("Study: " + study);
                SimpleEntry<Boolean, String> validate;
                try {
                    validate = this.simvaKeycloakCheck.checkTokenInStudy(study, username);
                } catch(IOException e) {
                    logger.info(e.toString());
                    validate = new SimpleEntry<>(false, null);
                }
                if(validate.getKey()) {
                    String updatedUsername = validate.getValue();
                    // Set the new username in the authentication session
                    context.setUser(context.getSession().users().getUserByUsername(context.getRealm(), updatedUsername));
                    context.success(); // Proceed if token is valid
                    return;
                } else {
                    if(study != "") {
                        stringurl.append("&login_hint=").append(study);
                    }
                    stringurl.append("&simva_user_token=true");
                    logger.info(stringurl.toString());
                    // Create a form error response
                    Response challengeResponse = context.form()
                        .setError(errorMsg)
                        .setAttribute("hideLocaleDropdown", hideLocaleDropdown)
                        .setAttribute("simvaUserToken", "true")
                        .setAttribute("stringurl", stringurl.toString())
                        .createForm("login.ftl");
                    context.challenge(challengeResponse);
                }
            } else {
                if(username.isEmpty()) {
                    errorMsg=Messages.MISSING_USERNAME;
                } else if(password.isEmpty()) {
                    errorMsg=Messages.MISSING_PASSWORD;
                } else {
                    errorMsg=Messages.INVALID_USERNAME_OR_PASSWORD;
                }
                logger.info("AUTHENTICATE username password custom provider: " + username);
                Boolean valid;
                try {
                    valid = this.simvaKeycloakCheck.checkUsernamePassword(username, password);
                } catch(IOException e) {
                    logger.info(e.toString());
                    valid=false;
                }
                if(valid) {
                    // Set the username in the authentication session
                    context.setUser(context.getSession().users().getUserByUsername(context.getRealm(), username));
                    context.success(); // Proceed if token is valid
                    return;
                } else {
                    // Create a form error response
                    Response challengeResponse = context.form()
                        .setAttribute("hideLocaleDropdown", hideLocaleDropdown)
                        .setAttribute("stringurl", stringurl.toString())
                        .setError(errorMsg)
                        .createForm("login.ftl");
                    context.challenge(challengeResponse);
                }
            }
        }
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
