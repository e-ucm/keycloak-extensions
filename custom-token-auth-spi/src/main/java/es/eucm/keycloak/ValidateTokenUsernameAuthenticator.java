package es.eucm.keycloak;

import es.eucm.utils.SimvaApiClient;
import es.eucm.utils.KeycloakOAuth2Client;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.directgrant.AbstractDirectGrantAuthenticator;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.authentication.authenticators.util.AuthenticatorUtils;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import java.util.ArrayList;

import static org.keycloak.authentication.authenticators.util.AuthenticatorUtils.getDisabledByBruteForceEventError;

public class ValidateTokenUsernameAuthenticator extends AbstractDirectGrantAuthenticator {
    
    private final Logger logger = LoggerFactory.getLogger(ValidateTokenUsernameAuthenticator.class);
    public static final String PROVIDER_ID = "direct-grant-validate-token-username";
    private SimvaApiClient simvaClient;
    private KeycloakOAuth2Client keycloakClient;

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        //MultivaluedMap<String, String> queryData = context.getHttpRequest();
        //logMap(queryData);
        MultivaluedMap<String, String> inputData = context.getHttpRequest().getDecodedFormParameters();
        logMap(inputData);
        String username = inputData.getFirst(AuthenticationManager.FORM_USERNAME);
        logger.info("Username found is : " + username);

        if (username == null) {
            context.getEvent().error(Errors.USER_NOT_FOUND);
            Response challengeResponse = errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_request", "Missing parameter: username");
            context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
            return;
        }
        context.getEvent().detail(Details.USERNAME, username);
        context.getAuthenticationSession().setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, username);

        UserModel user = null;
        try {
            user = KeycloakModelUtils.findUserByNameOrEmail(context.getSession(), context.getRealm(), username);
        } catch (ModelDuplicateException mde) {
            ServicesLogger.LOGGER.modelDuplicateException(mde);
            Response challengeResponse = errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_request", "Invalid user credentials");
            context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
            return;
        }

        this.simvaClient = new SimvaApiClient();  // Initialize client from environment variables
        try {
            if(!this.simvaClient.isAuthentificated()) {
                this.simvaClient.authenticate();
            }
        } catch(IOException e) {
            logger.info(e.toString());
        }
        this.keycloakClient = new KeycloakOAuth2Client();

        try {
            if(this.keycloakClient.validateUserCredentials(username, username)) {
                logger.info("Validated token");
            } else {
                logger.info("Invalidated token");
            }
        } catch(IOException e){
            logger.info(e.toString());
        }

        if (user == null) {
            //AuthenticatorUtils.dummyHash(context);
            context.getEvent().error(Errors.USER_NOT_FOUND);
            Response challengeResponse = errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_grant", "Invalid user credentials");
            context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
            return;
        }
        
        String bruteForceError = getDisabledByBruteForceEventError(context, user);
        if (bruteForceError != null) {
            //AuthenticatorUtils.dummyHash(context);
            context.getEvent().user(user);
            context.getEvent().error(bruteForceError);
            Response challengeResponse = errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_grant", "Invalid user credentials");
            context.forceChallenge(challengeResponse);
            return;
        }

        if (!user.isEnabled()) {
            context.getEvent().user(user);
            context.getEvent().error(Errors.USER_DISABLED);
            Response challengeResponse = errorResponse(Response.Status.BAD_REQUEST.getStatusCode(), "invalid_grant", "Account disabled");
            context.forceChallenge(challengeResponse);
            return;
        }

        context.setUser(user);
        context.success();
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
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

    }

    @Override
    public String getDisplayType() {
        return "Username Token Validation";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    public static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED
    };

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
       return REQUIREMENT_CHOICES;
    }
    
    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Validates the token username supplied as a 'username' form parameter in direct grant request";
    }

    private static final List<ProviderConfigProperty> configProperties=new ArrayList<>();

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
 }
