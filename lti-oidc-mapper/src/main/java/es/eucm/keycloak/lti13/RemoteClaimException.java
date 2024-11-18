package es.eucm.keycloak.lti13;

public class RemoteClaimException extends RuntimeException {

    /**
     * @see java.io.Serializable
     */
    private static final long serialVersionUID = 1L;

    public RemoteClaimException(String message, String url) {
        super(message + " - endpoint URL: " + url);
    }

    public RemoteClaimException(String message, String url, Throwable cause) {
        super(message + " - endpoint URL: " + url, cause);
    }

}