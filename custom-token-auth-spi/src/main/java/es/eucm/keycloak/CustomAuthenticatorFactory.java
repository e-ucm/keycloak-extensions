package es.eucm.keycloak;

import es.eucm.keycloak.CustomAuthenticator;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * Factory class for creating {@link CustomAuthenticator} instances.
 * 
 * <p>This factory is registered as a Keycloak Service Provider Interface (SPI)
 * and allows the CustomAuthenticator to be selected and configured in Keycloak's
 * authentication flow configuration.</p>
 * 
 * <h2>Provider Registration</h2>
 * <p>The factory is registered via {@code META-INF/services/org.keycloak.authentication.AuthenticatorFactory}
 * with the provider ID {@value #PROVIDER_ID}.</p>
 * 
 * <h2>Authentication Flow Integration</h2>
 * <p>To use this authenticator:</p>
 * <ol>
 *   <li>Navigate to Authentication → Flows in Keycloak Admin Console</li>
 *   <li>Create or copy a browser flow</li>
 *   <li>Add an execution step and select "Token Authenticator"</li>
 *   <li>Set the requirement to REQUIRED</li>
 * </ol>
 * 
 * @author e-UCM Research Group
 * @see CustomAuthenticator
 */
public class CustomAuthenticatorFactory implements AuthenticatorFactory {

    private final Logger log = LoggerFactory.getLogger(CustomAuthenticatorFactory.class);
    
    /**
     * Unique identifier for this authenticator provider.
     * Used in configuration files and admin console.
     */
    public static final String PROVIDER_ID = "token-authenticator";

    AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = new AuthenticationExecutionModel.Requirement[]{AuthenticationExecutionModel.Requirement.REQUIRED};
    
    /**
     * Creates a new CustomAuthenticator instance for the given session.
     * 
     * @param session The Keycloak session context
     * @return A new CustomAuthenticator instance
     */
    @Override
    public Authenticator create(KeycloakSession session) {
        return new CustomAuthenticator(session);
    }

    /**
     * Initializes the factory. Called once when Keycloak starts.
     * 
     * @param config Configuration scope for this provider
     */
    @Override
    public void init(Config.Scope config) {
        //Initialize the provider
    }

    /**
     * Post-initialization callback. Called after all providers are initialized.
     * 
     * @param factory The Keycloak session factory
     */
    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // Post initialization
    }

    /**
     * Cleanup callback. Called when Keycloak shuts down.
     */
    @Override
    public void close() {
        // Close the provider
    }

    /**
     * Returns the unique provider identifier.
     * 
     * @return The provider ID "token-authenticator"
     */
    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    /**
     * Returns the display name shown in admin console.
     * 
     * @return "Token Authenticator"
     */
    @Override
    public String getDisplayType() {
        return "Token Authenticator";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public String getHelpText() {
        return "Customised authenticator to authenticate the user via a token";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }
}
