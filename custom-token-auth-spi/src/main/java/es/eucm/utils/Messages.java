package es.eucm.utils;

/**
 * Constants for error message keys used in authentication flows.
 * 
 * <p>These message keys correspond to entries in the Keycloak theme's
 * message properties files (e.g., messages_en.properties). The authenticator
 * sets these keys as error messages, and the theme resolves them to
 * localized text.</p>
 * 
 * <h2>Standard Keycloak Messages</h2>
 * <p>Some keys (like invalidUserMessage) are standard Keycloak message keys
 * that already have translations in the base theme.</p>
 * 
 * <h2>Custom SIMVA Messages</h2>
 * <p>Keys prefixed with "error-" are custom messages that must be defined
 * in the SIMVA theme's message properties files:</p>
 * <ul>
 *   <li>messages_en.properties (English)</li>
 *   <li>messages_es.properties (Spanish)</li>
 *   <li>messages_fr.properties (French)</li>
 * </ul>
 * 
 * <h2>Usage</h2>
 * <pre>
 * // In authenticator code:
 * context.form()
 *     .setError(Messages.INVALID_TOKEN)
 *     .createLoginUsernamePassword();
 * </pre>
 * 
 * @author e-UCM Research Group
 * @see CustomAuthenticator
 * @see ValidateTokenUsernameAuthenticator
 */
public interface Messages {
    
    // ==================== Standard Keycloak Messages ====================
    
    /** Standard message for invalid username or password */
    String INVALID_USERNAME_OR_PASSWORD = "invalidUserMessage";
    
    /** Standard message for missing username field */
    String MISSING_USERNAME = "missingUsernameMessage";
    
    /** Standard message for missing password field */
    String MISSING_PASSWORD = "missingPasswordMessage";
    
    // ==================== Validation Error Messages ====================
    
    /** Generic invalid value error */
    String INVALID_VALUE = "error-invalid-value";
    
    /** Empty field error */
    String EMPTY_VALUE = "error-empty";
    
    // ==================== Scheduler Error Messages ====================
    
    /** 
     * Token is invalid or not found in any study group.
     * Displayed when the submitted token cannot be validated.
     */
    String INVALID_TOKEN = "error-invalid-token";
    
    /** 
     * Scheduler configuration is invalid.
     * Displayed when study/session in request doesn't match scheduler.
     */
    String INVALID_SCHEDULER = "error-invalid-scheduler";
    
    /** 
     * The requested activity is not the current scheduled activity.
     * User must complete activities in order.
     */
    String NOT_CURRENT_ACTIVITY = "error-not-current-activity";
    
    /** 
     * Activity was already completed and cannot be restarted.
     * The activity's restart setting prevents re-access.
     */
    String ACTIVITY_CANNOT_BE_RESTARTED = "error-activity-cannot-be-restarted";
    
    /** 
     * User is not a participant in the requested study.
     * They need to be added to a study group first.
     */
    String USER_NOT_PARTICIPANT = "error-user-not-participant";
    
    /** 
     * No scheduler information found for the study.
     * The study may not have a schedule configured.
     */
    String NO_SCHEDULER_INFO = "error-no-scheduler-info";
    
    /** 
     * Token users must authenticate using their token, not username/password.
     * Prevents token users from bypassing token-based access control.
     */
    String TOKEN_USER_MUST_USE_TOKEN_AUTHENTIFICATION = "error-token-user-must-use-token-authentication";
    
    /** 
     * The session is not active yet.
     * Displayed when trying to access a scheduled session before its start time.
     */
    String SESSION_NOT_ACTIVE = "error-session-not-active";
}