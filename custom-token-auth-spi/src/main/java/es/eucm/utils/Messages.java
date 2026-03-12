package es.eucm.utils;

public interface Messages {
    String INVALID_USERNAME_OR_PASSWORD = "invalidUserMessage";
    String MISSING_USERNAME = "missingUsernameMessage";
    String MISSING_PASSWORD = "missingPasswordMessage";
    String INVALID_VALUE = "error-invalid-value";
    String EMPTY_VALUE = "error-empty";
    
    // Scheduler error messages
    String INVALID_TOKEN = "error-invalid-token";
    String INVALID_SCHEDULER = "error-invalid-scheduler";
    String NOT_CURRENT_ACTIVITY = "error-not-current-activity";
    String ACTIVITY_CANNOT_BE_RESTARTED = "error-activity-cannot-be-restarted";
    String USER_NOT_PARTICIPANT = "error-user-not-participant";
    String NO_SCHEDULER_INFO = "error-no-scheduler-info";
    String TOKEN_USER_MUST_USE_TOKEN_AUTHENTIFICATION = "error-token-user-must-use-token-authentication";
}