package fr.cnieg.keycloak.providers.login.attribute.authenticator;

import java.util.ArrayList;
import java.util.List;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * Form factory for Attribute Username Password
 */
public class AttributeUsernamePasswordFormFactory implements AuthenticatorFactory {

    /**
     * Provider Id
     */
    public static final String PROVIDER_ID = "attribute-username-password-form";
    /**
     * Singleton instance
     */
    public static final AttributeUsernamePasswordForm SINGLETON = new AttributeUsernamePasswordForm();

    /**
     * @param session keycloak user session
     * @return authenticator
     */
    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    /**
     * @param config configuration provider
     */
    @Override
    public void init(Config.Scope config) {
        // unused method
    }

    /**
     * @param factory noop
     */
    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // unused method
    }

    /**
     * noop
     */
    @Override
    public void close() {
        // unused method
    }

    /**
     * @return provider id
     */
    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    /**
     * @return Model Type
     */
    @Override
    public String getReferenceCategory() {
        return PasswordCredentialModel.TYPE;
    }

    /**
     * @return configurable provider
     */
    @Override
    public boolean isConfigurable() {
        return true;
    }

    /**
     * Choices are required
     */
    protected static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = { AuthenticationExecutionModel.Requirement.REQUIRED };

    /**
     * @return requirements
     */
    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    /**
     * @return no user setup allowed
     */
    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    /**
     * @return Form display
     */
    @Override
    public String getDisplayType() {
        return "Attribute Username Password Form";
    }

    /**
     * @return Help Text
     */
    @Override
    public String getHelpText() {
        return "Validates a username or attribute and password from login form";
    }

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

    static {
        ProviderConfigProperty providerConfigProperty = new ProviderConfigProperty();
        providerConfigProperty.setName(AttributeUsernamePasswordForm.ATTRIBUTE_KEY);
        providerConfigProperty.setLabel("User Attribute");
        providerConfigProperty.setType(ProviderConfigProperty.STRING_TYPE);
        providerConfigProperty.setHelpText("User attribute that can be used as an alternative identifier ");
        CONFIG_PROPERTIES.add(providerConfigProperty);
        providerConfigProperty = new ProviderConfigProperty();
        providerConfigProperty.setName(AttributeUsernamePasswordForm.ATTRIBUTE_REGEX);
        providerConfigProperty.setLabel("Attribute Regular Expression");
        providerConfigProperty.setType(ProviderConfigProperty.STRING_TYPE);
        providerConfigProperty.setHelpText("Regular expression for which the search by attribute will be performed");
        providerConfigProperty.setDefaultValue(".*");
        CONFIG_PROPERTIES.add(providerConfigProperty);
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }
}