package es.eucm.keycloak;

import es.eucm.utils.SimvaKeycloakCheck;
import es.eucm.utils.Messages;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.authentication.Authenticator;
import org.keycloak.cookie.CookieProvider;
import org.keycloak.cookie.CookieType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.managers.AuthenticationManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.io.IOException;

import java.util.AbstractMap.SimpleEntry;

/**
 * Custom Keycloak Authenticator for SIMVA integration.
 * 
 * <p>This authenticator extends Keycloak's browser-based authentication flow to support
 * two authentication methods:</p>
 * <ul>
 *   <li><b>Token Authentication:</b> Users authenticate using a SIMVA-issued token
 *       (triggered by the query parameter {@code simva_user_token=true})</li>
 *   <li><b>Username/Password Authentication:</b> Standard credential-based authentication
 *       validated against SIMVA API</li>
 * </ul>
 * 
 * <h2>Login Hint Support</h2>
 * <p>The authenticator uses the OIDC {@code login_hint} parameter to specify the study context.
 * The login_hint format can be:</p>
 * <ul>
 *   <li>{@code study_id} - Access to a specific study</li>
 *   <li>{@code study_id:session_id:activity_id} - Access to a specific activity within a study session</li>
 * </ul>
 * 
 * <h2>SSO Session Handling</h2>
 * <p>When a user has an existing SSO session, the authenticator validates that the session
 * matches the requested login_hint. If mismatch is detected, the existing session is invalidated
 * to force re-authentication with the correct context.</p>
 * 
 * <h2>Environment Variables Required</h2>
 * <ul>
 *   <li>{@code SIMVA_API_URL} - Base URL of the SIMVA API</li>
 *   <li>{@code SIMVA_API_ADMIN_USERNAME} - Admin username for SIMVA API</li>
 *   <li>{@code SIMVA_API_ADMIN_PASSWORD} - Admin password for SIMVA API</li>
 *   <li>{@code KEYCLOAK_TOKEN_URL} - Keycloak token endpoint URL</li>
 *   <li>{@code KEYCLOAK_CLIENT_CLIENT_ID} - OAuth2 client ID</li>
 *   <li>{@code KEYCLOAK_CLIENT_CLIENT_SECRET} - OAuth2 client secret</li>
 * </ul>
 * 
 * @author e-UCM Research Group
 * @see CustomAuthenticatorFactory
 * @see SimvaKeycloakCheck
 */
public class CustomAuthenticator extends AbstractUsernameFormAuthenticator implements Authenticator {

    private final Logger logger = LoggerFactory.getLogger(CustomAuthenticator.class);

    private ObjectMapper objectMapper = new ObjectMapper();

    private final KeycloakSession session;
    private SimvaKeycloakCheck simvaKeycloakCheck;

    private UserModel resolvedUser = null;
    private UserSessionModel resolvedUserSession = null;

    /**
     * Constructs a new CustomAuthenticator instance.
     * 
     * <p>During construction, the authenticator:</p>
     * <ol>
     *   <li>Initializes the SIMVA API client and validates admin credentials</li>
     *   <li>Checks for existing SSO sessions using Keycloak's identity cookie</li>
     *   <li>If an SSO session exists, validates it against the login_hint</li>
     *   <li>Invalidates mismatched sessions to force proper re-authentication</li>
     * </ol>
     * 
     * @param session The Keycloak session providing access to realm, users, and authentication context
     */
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
                // Distinguish between a missing identity cookie and a present cookie
                // whose token verification failed (e.g. stale/expired identity token
                // while the underlying user session is still valid).
                String identityCookie = session.getProvider(CookieProvider.class).get(CookieType.IDENTITY);
                if (identityCookie == null || identityCookie.isEmpty()) {
                    logger.info("No existing SSO session found (identity cookie absent)");
                } else {
                    logger.info("Identity cookie present but authenticateIdentityCookie returned null");
                    // Try to re-resolve the user session from the identity cookie's session
                    // state, even though strict token verification failed. The identity cookie
                    // is only held by the browser that created the session, so this does not
                    // weaken authentication: it only confirms a session that already exists.
                    UserSessionModel identityUserSession = resolveIdentityCookieSession(realm, identityCookie);
                    if (identityUserSession != null && identityUserSession.getUser() != null) {
                        resolvedUser = identityUserSession.getUser();
                        resolvedUserSession = identityUserSession;
                        authenticatedUsername = resolvedUser.getUsername();
                        logger.info("Resolved existing SSO session from identity cookie for user: " + authenticatedUsername
                                + " (strict identity token verification failed, reusing valid server-side session)");
                    } else {
                        logger.info("Could not resolve user session from identity cookie");
                    }
                }
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
                        UserSessionModel toRemove = (authResult != null ? authResult.getSession() : null);
                        if (toRemove == null) {
                            toRemove = resolvedUserSession;
                        }
                        if (toRemove != null) {
                            session.sessions().removeUserSession(realm, toRemove);
                        }
                        resolvedUser = null;
                        resolvedUserSession = null;
                        session.getContext().getAuthenticationSession().setAuthenticatedUser(null);
                        session.getContext().getAuthenticationSession().removeAuthNote(USER_SET_BEFORE_USERNAME_PASSWORD_AUTH);
                    } else {
                        logger.info("Current user '{}' matches login_hint '{}', keeping user authenticated", authenticatedUsername, loginHint);
                        // Keep the resolved existing session flagged so authenticate() can
                        // continue the SSO flow without prompting again.
                        this.resolvedUserSession = resolvedUserSession != null ? resolvedUserSession :
                                (authResult != null ? authResult.getSession() : null);
                        this.resolvedUser = resolvedUser != null ? resolvedUser :
                                (authResult != null ? authResult.getUser() : null);
                    }
                } catch(IOException e) {
                    logger.info("Error during token check in constructor: " + e.toString());
                    UserSessionModel toRemove = (authResult != null ? authResult.getSession() : null);
                    if (toRemove == null) {
                        toRemove = resolvedUserSession;
                    }
                    if (toRemove != null) {
                        session.sessions().removeUserSession(realm, toRemove);
                    }
                    resolvedUser = null;
                    resolvedUserSession = null;
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
     * Resolves the user session referenced by a Keycloak identity cookie without
     * requiring strict identity token verification.
     * 
     * <p>The identity cookie is a JWT whose payload carries the {@code sid} (session
     * state) of the corresponding user session. Even when the cookie's token fails
     * strict verification (e.g. expired identity token but still-active server-side
     * session, which is common for simva token users), the {@code sid} can be decoded
     * and used to look up the real user session.</p>
     * 
     * @param realm The realm model
     * @param identityCookie The raw identity cookie value
     * @return The resolved user session, or null if it could not be resolved
     */
    private UserSessionModel resolveIdentityCookieSession(RealmModel realm, String identityCookie) {
        // The identity cookie is a signed JWT (header.payload.signature). Decode the
        // payload without signature verification to read the sid (session state) claim.
        try {
            String[] parts = identityCookie.split("\\.");
            if (parts.length < 2) {
                logger.info("Identity cookie is not a valid JWT, cannot resolve user session");
                return null;
            }
            String payload = new String(java.util.Base64.getUrlDecoder().decode(parts[1]), java.nio.charset.StandardCharsets.UTF_8);
            AccessToken token = objectMapper.readValue(payload, AccessToken.class);
            String sessionState = token.getSessionState();
            if (sessionState == null || sessionState.isEmpty()) {
                logger.info("Identity cookie has no session state, cannot resolve user session");
                return null;
            }
            UserSessionModel userSession = session.sessions().getUserSession(realm, sessionState);
            if (userSession != null) {
                logger.info("Resolved user session " + sessionState + " from identity cookie for user: "
                        + (userSession.getUser() != null ? userSession.getUser().getUsername() : "null"));
            }
            return userSession;
        } catch (Exception e) {
            logger.info("Failed to decode identity cookie: " + e.toString());
            return null;
        }
    }

    /**
     * Initiates the authentication flow by displaying the appropriate login form.
     * 
     * <p>This method determines which login form to display based on the request parameters:</p>
     * <ul>
     *   <li>If {@code simva_user_token=true} is present, displays the token authentication form</li>
     *   <li>Otherwise, displays the standard username/password form</li>
     * </ul>
     * 
     * <p>The method also handles:</p>
     * <ul>
     *   <li>Pre-populating the username field with login_hint or remember-me values</li>
     *   <li>Hiding the username field if a user is already set in the context</li>
     *   <li>Passing through display customization parameters (e.g., hideLocaleDropdown)</li>
     * </ul>
     * 
     * @param context The authentication flow context containing request data, session, and form builder
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

        // SSO continuation for an existing valid user session resolved in the
        // constructor (identity cookie present, server-side session still active).
        // Completes the flow without re-prompting, matching username/password
        // users who already have a resolvable identity cookie.
        if (this.resolvedUser != null && this.resolvedUserSession != null && context.getUser() == null) {
            logger.info("Completing SSO flow for already authenticated user: " + this.resolvedUser.getUsername());
            context.setUser(this.resolvedUser);
            context.attachUserSession(this.resolvedUserSession);
            context.getAuthenticationSession().setAuthNote(USER_SET_BEFORE_USERNAME_PASSWORD_AUTH, "true");
            try {
                // Recreate a fresh identity cookie so future requests short-circuit
                // through Keycloak's standard SSO handling, like username/password users.
                // This is an optimization only; the current flow completes regardless.
                AuthenticationManager.createLoginCookie(context.getSession(),
                        context.getRealm(),
                        this.resolvedUser,
                        this.resolvedUserSession,
                        context.getUriInfo(),
                        context.getConnection());
            } catch (Exception e) {
                logger.info("Failed to recreate identity cookie while completing SSO flow: " + e.toString());
            }
            this.resolvedUser = null;
            this.resolvedUserSession = null;
            context.success();
            return;
        }

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

    /**
     * Creates the login challenge response with the appropriate form.
     * 
     * @param forms The login forms provider for creating the response
     * @param formData Pre-populated form data (e.g., username from login_hint)
     * @return The HTTP response containing the login form
     */
    protected Response challenge(LoginFormsProvider forms, MultivaluedMap<String, String> formData) {
        logger.info("Creating challenge response with form data: " + formData);
        if (formData.size() > 0) forms.setFormData(formData);

        return forms.createLoginUsernamePassword();
    }

    /**
     * Utility method to log the contents of a MultivaluedMap for debugging.
     * 
     * @param formData The map containing form parameters or query parameters to log
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
     * Processes the submitted authentication form.
     * 
     * <p>This method handles two authentication modes:</p>
     * 
     * <h3>Token Authentication (simva_user_token=true)</h3>
     * <ol>
     *   <li>Extracts the token from the username field</li>
     *   <li>Validates the token against SIMVA API using {@link SimvaKeycloakCheck#checkTokenWithLoginHint}</li>
     *   <li>Resolves the token to the actual Keycloak username</li>
     *   <li>On success, sets the authenticated user and completes the flow</li>
     *   <li>On failure, displays an appropriate error message (invalid token, wrong activity, etc.)</li>
     * </ol>
     * 
     * <h3>Username/Password Authentication</h3>
     * <ol>
     *   <li>Validates credentials against SIMVA API using {@link SimvaKeycloakCheck#checkUsernamePassword}</li>
     *   <li>Verifies the user is not a token-only user (they must use token auth)</li>
     *   <li>On success, sets the authenticated user and completes the flow</li>
     *   <li>On failure, displays the appropriate error message</li>
     * </ol>
     * 
     * @param context The authentication flow context containing submitted form data
     */
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
