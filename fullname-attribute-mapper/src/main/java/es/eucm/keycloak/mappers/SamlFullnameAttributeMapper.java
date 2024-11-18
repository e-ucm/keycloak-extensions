package es.eucm.keycloak.mappers;

import org.keycloak.protocol.saml.mappers.AttributeStatementHelper;
import org.keycloak.protocol.saml.mappers.AbstractSAMLProtocolMapper;
import org.keycloak.protocol.saml.mappers.SAMLAttributeStatementMapper;
import org.keycloak.dom.saml.v2.assertion.AttributeStatementType;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

/**
 * Mappings UserModel property (the property name of a getter method) to an AttributeStatement.
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class SamlFullnameAttributeMapper extends AbstractSAMLProtocolMapper implements SAMLAttributeStatementMapper {
    public static final String PROVIDER_ID = "saml-fullname-attribute-mapper";
    public static final String ATTRIBUTE_VALUE = "attribute.value";
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();

    static {
        AttributeStatementHelper.setConfigProperties(configProperties);
        /*
        ProviderConfigProperty property;
        property = new ProviderConfigProperty();
        property.setName(ATTRIBUTE_VALUE);
        property.setLabel("Attribute value");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Value of the attribute you want to hard code.");
        configProperties.add(property);
        */
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getDisplayType() {
        return "Fullname attribute";
    }

    @Override
    public String getDisplayCategory() {
        return AttributeStatementHelper.ATTRIBUTE_STATEMENT_CATEGORY;
    }

    @Override
    public String getHelpText() {
        return "Add an attribute into the SAML Assertion with User name and Lastname concatenated.";
    }

    @Override
    public void transformAttributeStatement(AttributeStatementType attributeStatement, ProtocolMapperModel mappingModel, KeycloakSession session, UserSessionModel userSession, AuthenticatedClientSessionModel clientSession) {
        UserModel user = userSession.getUser();
        String name = user.getFirstName();
        String lastName = user.getLastName();
        String fullName = name;

        if (name == null) return;
        if (lastName != null && lastName.trim().length() != 0) {
            fullName = name + " " + lastName.trim();
        }

        AttributeStatementHelper.addAttribute(attributeStatement, mappingModel, fullName);
    }

    public static ProtocolMapperModel create(String name,
                                             String samlAttributeName, String nameFormat, String friendlyName, String value) {
        String mapperId = PROVIDER_ID;
        ProtocolMapperModel model = AttributeStatementHelper.createAttributeMapper(name, null, samlAttributeName, nameFormat, friendlyName,
                mapperId);
        //model.getConfig().put(ATTRIBUTE_VALUE, value);
        return model;

    }

}