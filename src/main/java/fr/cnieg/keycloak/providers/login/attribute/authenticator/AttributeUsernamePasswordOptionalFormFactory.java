package fr.cnieg.keycloak.providers.login.attribute.authenticator;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.models.credential.WebAuthnCredentialModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.authentication.authenticators.browser.WebAuthnConditionalUIAuthenticator;

/**
 * Form factory for Attribute Username Password (Optional/Hidden for password managers)
 */
public class AttributeUsernamePasswordOptionalFormFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "attribute-username-password-opt-form";

    @Override
    public Authenticator create(KeycloakSession session) {
        return new AttributeUsernamePasswordOptionalForm(session);
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getReferenceCategory() {
        return PasswordCredentialModel.TYPE;
    }

    @Override
    public Set<String> getOptionalReferenceCategories(KeycloakSession session) {
        return WebAuthnConditionalUIAuthenticator.isPasskeysEnabled(session)
                ? Collections.singleton(WebAuthnCredentialModel.TYPE_PASSWORDLESS)
                : AuthenticatorFactory.super.getOptionalReferenceCategories(session);
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    public static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED
    };

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public String getDisplayType() {
        return "Attribute Username Password-Optional Form";
    }

    @Override
    public String getHelpText() {
        return "Validates a username or attribute and optional password from login form.";
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
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
