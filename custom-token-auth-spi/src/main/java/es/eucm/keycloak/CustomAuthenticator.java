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
import org.keycloak.models.UserSessionModel;
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
        logger.info("CustomAuthenticator constructor called");
        simvaKeycloakCheck= new SimvaKeycloakCheck();
        this.session = session;
        if(this.session != null) {
            logger.info("Session already set in constructor: " + this.session);
            String loginHint = session.getContext().getAuthenticationSession().getClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM);
            logger.info("Login hint in constructor: " + loginHint);
            
            // Check for existing SSO session using identity cookie
            RealmModel realm = session.getContext().getRealm();
            AuthenticationManager.AuthResult authResult = AuthenticationManager.authenticateIdentityCookie(session, realm, true);
            
            String authenticatedUsername = null;
            if (authResult != null && authResult.getUser() != null) {
                authenticatedUsername = authResult.getUser().getUsername();
                logger.info("Found existing SSO session for user: " + authenticatedUsername);
            } else {
                logger.info("No existing SSO session found");
            }
            
            if(authenticatedUsername != null) {
                try {
                    SimpleEntry<Boolean, String> checkResult;
                    if (loginHint != null && !loginHint.isEmpty()) {
                        logger.info("Checking login_hint against current already authenticated user: " + authenticatedUsername);
                        checkResult = simvaKeycloakCheck.checkTokenWithLoginHint(authenticatedUsername, loginHint, true);
                    } else {
                        logger.info("No login_hint provided, checking user check for already authenticated user");
                        checkResult = simvaKeycloakCheck.checkUserAccessNotATokenForAuthenticatedUser(authenticatedUsername);
                    }
                    if (!checkResult.getKey()) {
                        String errorReason = checkResult.getValue() != null ? checkResult.getValue() : "unknown";
                        logger.info("Current user '{}' does not match login_hint '{}', reason: {}, invalidating SSO session", authenticatedUsername, loginHint, errorReason);
                        // Invalidate the existing session so user has to re-authenticate
                        if (authResult != null && authResult.getSession() != null) {
                            session.sessions().removeUserSession(realm, authResult.getSession());
                        }
                        session.getContext().getAuthenticationSession().setAuthenticatedUser(null);
                        session.getContext().getAuthenticationSession().removeAuthNote(USER_SET_BEFORE_USERNAME_PASSWORD_AUTH);
                    } else {
                        logger.info("Current user '{}' matches login_hint '{}', keeping user authenticated", authenticatedUsername, loginHint);
                    }
                } catch(IOException e) {
                    logger.info("Error during token check in constructor: " + e.toString());
                    if (authResult != null && authResult.getSession() != null) {
                        session.sessions().removeUserSession(realm, authResult.getSession());
                    }
                    session.getContext().getAuthenticationSession().setAuthenticatedUser(null);
                    session.getContext().getAuthenticationSession().removeAuthNote(USER_SET_BEFORE_USERNAME_PASSWORD_AUTH);
                }
            } else if (authenticatedUsername == null) {
                logger.info("No user authenticated in constructor");
            }
        } else {
            logger.info("Session is null in constructor");
        }
       
    }

    /**
     * Method is used for user authentication. It authentificate via password and username or via token and that returns a jwt token if the user is authenticated
     * If the user is authenticated an authenticated user is set.
     * Whereas if the user is not authenticated, an error is set.
     * @param context
     */
    @Override
    public void authenticate(AuthenticationFlowContext context) {
        logger.info("CUSTOMER PROVIDER authenticate method called");
        logger.info("Actual User: " + context.getUser());
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
        if(simvaUserTokenPresent != null && simvaUserTokenPresent.equals("true")) {
            String login_hint = context.getHttpRequest().getUri().getQueryParameters().getFirst("login_hint");
            if(login_hint != null && !login_hint.isEmpty()) {
                stringurl.append("&login_hint=").append(login_hint);
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
        logger.info("Creating challenge response with form data: " + formData);
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
        logger.info("CUSTOMER PROVIDER action method called");
        logger.info("Actual User: " + context.getUser());
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
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
        if(simvaUserTokenPresent != null && simvaUserTokenPresent.equals("true")) {
                if(username.isEmpty()) {
                    errorMsg=Messages.EMPTY_VALUE;
                } else {
                    errorMsg=Messages.INVALID_VALUE;
                }
                logger.info("AUTHENTICATE token custom provider: " + username);
                String login_hint = context.getHttpRequest().getUri().getQueryParameters().getFirst("login_hint");
                logger.info("Study: " + login_hint);
                SimpleEntry<Boolean, String> validate;
                try {
                    validate = this.simvaKeycloakCheck.checkTokenWithLoginHint(username, login_hint, false);
                } catch(IOException e) {
                    logger.info(e.toString());
                    validate = new SimpleEntry<>(false, Messages.INVALID_VALUE);
                }
                if(validate.getKey()) {
                    String updatedUsername = validate.getValue();
                    // Set the new username in the authentication session
                    UserModel user = context.getSession().users().getUserByUsername(context.getRealm(), updatedUsername);
                    if (user == null) {
                        logger.info("User not found in Keycloak: " + updatedUsername);
                        if(login_hint != null && !login_hint.isEmpty()) {
                            stringurl.append("&login_hint=").append(login_hint);
                        }
                        stringurl.append("&simva_user_token=true");
                        Response challengeResponse = context.form()
                            .setError(Messages.INVALID_VALUE)
                            .setAttribute("hideLocaleDropdown", hideLocaleDropdown)
                            .setAttribute("simvaUserToken", "true")
                            .setAttribute("stringurl", stringurl.toString())
                            .createLoginUsernamePassword();
                        context.challenge(challengeResponse);
                        return;
                    }
                    context.setUser(user);
                    context.success(); // Proceed if token is valid
                    return;
                } else {
                    // Use specific error message from validation if available
                    String specificError = validate.getValue();
                    if (specificError != null && !specificError.isEmpty()) {
                        errorMsg = specificError;
                    }
                    if(login_hint != null && !login_hint.isEmpty()) {
                        stringurl.append("&login_hint=").append(login_hint);
                    }
                    stringurl.append("&simva_user_token=true");
                    logger.info("Validation failed with error: " + errorMsg);
                    // Create a form error response
                    Response challengeResponse = context.form()
                        .setError(errorMsg)
                        .setAttribute("hideLocaleDropdown", hideLocaleDropdown)
                        .setAttribute("simvaUserToken", "true")
                        .setAttribute("stringurl", stringurl.toString())
                        .createLoginUsernamePassword();
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
                SimpleEntry<Boolean, String> validateResult;
                try {
                    validateResult = this.simvaKeycloakCheck.checkUsernamePassword(username, password);
                } catch(IOException e) {
                    logger.info(e.toString());
                    validateResult = new SimpleEntry<>(false, Messages.INVALID_USERNAME_OR_PASSWORD);
                }
                if(validateResult.getKey()) {
                    // Set the username in the authentication session
                    UserModel user = context.getSession().users().getUserByUsername(context.getRealm(), username);
                    if (user == null) {
                        logger.info("User not found in Keycloak: " + username);
                        Response challengeResponse = context.form()
                            .setAttribute("hideLocaleDropdown", hideLocaleDropdown)
                            .setAttribute("stringurl", stringurl.toString())
                            .setError(errorMsg)
                            .createLoginUsernamePassword();
                        context.challenge(challengeResponse);
                        return;
                    }
                    context.setUser(user);
                    context.success(); // Proceed if token is valid
                    return;
                } else {
                    // Use specific error message from validation if available
                    String specificError = validateResult.getValue();
                    if (specificError != null && !specificError.isEmpty()) {
                        errorMsg = specificError;
                    }
                    // Create a form error response
                    Response challengeResponse = context.form()
                        .setAttribute("hideLocaleDropdown", hideLocaleDropdown)
                        .setAttribute("stringurl", stringurl.toString())
                        .setError(errorMsg)
                        .createLoginUsernamePassword();
                    context.challenge(challengeResponse);
                }
            }
    }
    
    @Override
    public boolean requiresUser() {
        logger.info("CUSTOMER PROVIDER requiresUser method called");
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        logger.info("CUSTOMER PROVIDER configuredFor method called");
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        logger.info("CUSTOMER PROVIDER setRequiredActions method called");
        // Set the required actions for the user after authentication
    }

    @Override
    public void close() {
        logger.info("CUSTOMER PROVIDER close method called");
        // Closes any open resources
    }
}
