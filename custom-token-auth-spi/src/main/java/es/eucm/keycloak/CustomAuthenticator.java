package es.eucm.keycloak;

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


public class CustomAuthenticator extends AbstractUsernameFormAuthenticator implements Authenticator {

    private final Logger log = LoggerFactory.getLogger(CustomAuthenticator.class);

    private ObjectMapper objectMapper = new ObjectMapper();

    private final KeycloakSession session;

    public CustomAuthenticator(KeycloakSession session) {
        this.session = session;
    }

    /**
     * Method is used for user authentication. It authentificate via password and username or via token and that returns a jwt token if the user is authenticated
     * If the user is authenticated an authenticated user is set.
     * Whereas if the user is not authenticated, an error is set.
     * @param context
     */
    @Override
    public void authenticate(AuthenticationFlowContext context) {
        //logMap(context.getHttpRequest().getUri().getQueryParameters());
        String tokenPresent = context.getHttpRequest().getUri().getQueryParameters().getFirst("token");
        if(tokenPresent == null) {
            log.info("AUTHENTICATE username/password custom provider");
        } else {
            log.info("AUTHENTICATE token custom provider");
        }
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
        Response challengeResponse = challenge(context, formData);
        context.challenge(challengeResponse);
    }

    protected Response challenge(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        LoginFormsProvider forms = context.form();

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
        log.info("Data: {}", logMessage.toString());
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        //logMap(context.getHttpRequest().getUri().getQueryParameters());
        log.info("CUSTOMER PROVIDER action");
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        //logMap(formData);
        if (formData.containsKey("cancel")) {
            context.cancelLogin();
            return;
        }
        String username = formData.getFirst("username");
        String password = formData.getFirst("password");
        if(username.equals(password)) {
            log.info("AUTHENTICATE token custom provider: " + username);
            if(!validateForm(context, formData)) {
                // Create a form error response
                Response challengeResponse = context.form()
                    .setError("Missing or invalid token.")
                    .setAttribute("token", "true")
                    .createForm("login.ftl");
                context.challenge(challengeResponse);
            } else {
                context.success(); // Proceed if token is valid
            }
        } else {
            log.info("AUTHENTICATE username password custom provider: " + username);
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