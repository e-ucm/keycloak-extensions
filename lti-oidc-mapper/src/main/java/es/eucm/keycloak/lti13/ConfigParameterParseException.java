package es.eucm.keycloak.lti13;

public class ConfigParameterParseException extends RuntimeException {

    /**
     * @see java.io.Serializable
     */
    private static final long serialVersionUID = 1L;

    public ConfigParameterParseException(String message) {
        super(message);
    }
    
    public ConfigParameterParseException(String message, Throwable cause) {
        super(message, cause);
    }
}
