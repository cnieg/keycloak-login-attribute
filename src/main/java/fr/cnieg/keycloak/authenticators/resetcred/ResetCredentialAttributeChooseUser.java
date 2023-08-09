package fr.cnieg.keycloak.authenticators.resetcred;

import fr.cnieg.keycloak.providers.login.attribute.authenticator.AttributeUsernamePasswordForm;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.authenticators.resetcred.ResetCredentialChooseUser;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.List;

import static fr.cnieg.keycloak.AuthenticatorUserModel.getUserModel;

/**
 *
 */
public class ResetCredentialAttributeChooseUser extends ResetCredentialChooseUser implements Authenticator, AuthenticatorFactory {
    /**
     *
     */
    public static final String PROVIDER_ID = "reset-credentials-attr-choose-user";
    /**
     *
     */
    public static final String ATTRIBUTE_KEY = "login.attribute.key";
    /**
     *
     */
    public static final String ATTRIBUTE_REGEX = "login.attribute.regex";
    /**
     *
     */
    public static final String ATTRIBUTE_USERNAME = "username";

    /**
     * noop
     */
    public ResetCredentialAttributeChooseUser() {
        // noop
    }

    /**
     * @param context Keycloak context
     */
    @Override
    public void action(AuthenticationFlowContext context) {

        EventBuilder event = context.getEvent();
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String username = formData.getFirst(ATTRIBUTE_USERNAME);

        if (username != null && !username.isEmpty()) {
            username = username.trim();
            RealmModel realm = context.getRealm();

            // Get user by username
            UserModel user = context.getSession().users().getUserByUsername(realm, username);

            // Get user by email
            if (user == null && realm.isLoginWithEmailAllowed() && username.contains("@")) {
                user = context.getSession().users().getUserByEmail(realm, username);
            }

            // Get user by attribute
            if (user == null) {
                user = this.getUserByAttribute(context, username);
            }

            context.getAuthenticationSession().setAuthNote("ATTEMPTED_USERNAME", username);

            if (user == null) {
                event.clone().detail(ATTRIBUTE_USERNAME, username).error("user_not_found");
                context.clearUser();
            } else if (!user.isEnabled()) {
                event.clone().detail(ATTRIBUTE_USERNAME, username).user(user).error("user_disabled");
                context.clearUser();
            } else {
                context.setUser(user);
            }

            context.success();
        } else {
            event.error("username_missing");
            Response challenge = context.form().setError("missingUsernameMessage").createPasswordReset();
            context.failureChallenge(AuthenticationFlowError.INVALID_USER, challenge);
        }
    }

    private UserModel getUserByAttribute(AuthenticationFlowContext context, String userName) {
        return getUserModel(context, userName, ATTRIBUTE_KEY, ATTRIBUTE_REGEX);
    }

    /**
     * @return display type
     */
    @Override
    public String getDisplayType() {
        return "Attribute Choose User";
    }

    /**
     * @return configurable provider
     */
    @Override
    public boolean isConfigurable() {
        return true;
    }

    /**
     * @return provider id
     */
    @Override
    public String getId() {
        return PROVIDER_ID;
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

    /**
     * @return provider configuration
     */
    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }
}

