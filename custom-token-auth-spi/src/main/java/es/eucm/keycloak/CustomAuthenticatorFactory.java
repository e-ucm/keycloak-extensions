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


public class CustomAuthenticatorFactory implements AuthenticatorFactory {

    private final Logger log = LoggerFactory.getLogger(CustomAuthenticatorFactory.class);
    public static final String PROVIDER_ID = "token-authenticator";

    AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = new AuthenticationExecutionModel.Requirement[]{AuthenticationExecutionModel.Requirement.REQUIRED};
    
    @Override
    public Authenticator create(KeycloakSession session) {
        return new CustomAuthenticator(session);
    }

    @Override
    public void init(Config.Scope config) {
        //Initialize the provider
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // Post initialization
    }

    @Override
    public void close() {
        // Close the provider
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

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
