package es.eucm.keycloak;

import es.eucm.utils.SimvaKeycloakCheck;

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

import java.util.List;
import java.util.ArrayList;
import java.util.AbstractMap.SimpleEntry;

import static org.keycloak.authentication.authenticators.util.AuthenticatorUtils.getDisabledByBruteForceEventError;

/**
 * Direct Grant Authenticator for validating SIMVA tokens via the Resource Owner Password Grant.
 * 
 * <p>This authenticator extends Keycloak's Direct Grant (Resource Owner Password Credentials)
 * flow to support SIMVA token-based authentication. It is used for machine-to-machine
 * authentication where the client application directly submits credentials.</p>
 * 
 * <h2>Authentication Modes</h2>
 * <ul>
 *   <li><b>Token with Login Hint:</b> When {@code login_hint} parameter is present,
 *       the username is treated as a SIMVA token and validated against the study context</li>
 *   <li><b>Username/Password:</b> When no login_hint is present, standard credential
 *       validation is performed against SIMVA API</li>
 * </ul>
 * 
 * <h2>Request Parameters</h2>
 * <ul>
 *   <li>{@code username} - SIMVA token or username</li>
 *   <li>{@code password} - Password (same as token for token auth)</li>
 *   <li>{@code login_hint} - Study context in format {@code study_id} or {@code study_id:session_id:activity_id}</li>
 * </ul>
 * 
 * <h2>Usage Example</h2>
 * <pre>
 * POST /realms/{realm}/protocol/openid-connect/token
 * Content-Type: application/x-www-form-urlencoded
 * 
 * grant_type=password&amp;
 * client_id=simva-client&amp;
 * client_secret=secret&amp;
 * username=ABC123&amp;
 * password=ABC123&amp;
 * login_hint=study-001
 * </pre>
 * 
 * @author e-UCM Research Group
 * @see SimvaKeycloakCheck
 */
public class ValidateTokenUsernameAuthenticator extends AbstractDirectGrantAuthenticator {
    
    private final Logger logger = LoggerFactory.getLogger(ValidateTokenUsernameAuthenticator.class);
    
    /**
     * Unique identifier for this authenticator provider.
     */
    public static final String PROVIDER_ID = "direct-grant-validate-token-username";

    private SimvaKeycloakCheck simvaKeycloakCheck;

    /**
     * Authenticates a direct grant request by validating the submitted credentials.
     * 
     * <p>The authentication process:</p>
     * <ol>
     *   <li>If {@code login_hint} is present, validates username as a SIMVA token</li>
     *   <li>If no login_hint, validates username/password against SIMVA API</li>
     *   <li>Resolves the token to the actual Keycloak username</li>
     *   <li>Looks up the user in Keycloak and sets them in the context</li>
     *   <li>Performs brute force and disabled user checks</li>
     * </ol>
     * 
     * @param context The authentication flow context containing the request parameters
     */
    @Override
    public void authenticate(AuthenticationFlowContext context) {
        logger.info("ValidateTokenUsernameAuthenticator authenticate method called");
        this.simvaKeycloakCheck = new SimvaKeycloakCheck();
        MultivaluedMap<String, String> inputData = context.getHttpRequest().getDecodedFormParameters();
        logMap(inputData);
        String username = inputData.getFirst(AuthenticationManager.FORM_USERNAME);
        String login_hint = inputData.getFirst("login_hint");
        if (login_hint != null) {
            SimpleEntry<Boolean, String> validate;
            try {
                validate = this.simvaKeycloakCheck.checkTokenWithLoginHint(username, login_hint, false);
            } catch(IOException e) {
                logger.info(e.toString());
                validate = new SimpleEntry<>(false, null);
            }
            if(validate.getKey()) {
                username = validate.getValue();
            }
        } else {
            String password = inputData.getFirst("password");
            SimpleEntry<Boolean, String> validResult;
            try {
                validResult = this.simvaKeycloakCheck.checkUsernamePassword(username, password);
            } catch(IOException e) {
                logger.info(e.toString());
                validResult = new SimpleEntry<>(false, null);
            }
            if(validResult.getKey()) {
                logger.info("Username valid");
            } else {
                logger.info("Username not valid: " + validResult.getValue());
            }
        }
        
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

    /**
     * Utility method to log the contents of a MultivaluedMap for debugging.
     * 
     * @param formData The map containing form parameters to log
     */
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

    /**
     * Indicates whether this authenticator requires a user to be set before execution.
     * 
     * @return false - this authenticator identifies the user during execution
     */
    @Override
    public boolean requiresUser() {
        return false;
    }

    /**
     * Indicates whether this authenticator is configured for the given user.
     * 
     * @param session The Keycloak session
     * @param realm The realm
     * @param user The user model
     * @return true - always configured
     */
    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    /**
     * Sets required actions for the user after authentication.
     * 
     * @param session The Keycloak session
     * @param realm The realm
     * @param user The authenticated user
     */
    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

    }

    /**
     * Returns the display name shown in admin console.
     * 
     * @return "Username Token Validation"
     */
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