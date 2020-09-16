package fr.cnieg.keycloak.authenticators.resetcred;

import java.util.ArrayList;
import java.util.List;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.authenticators.resetcred.ResetCredentialChooseUser;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;

import fr.cnieg.keycloak.providers.login.attribute.authenticator.AttributeUsernamePasswordForm;

public class ResetCredentialAttributeChooseUser extends ResetCredentialChooseUser implements Authenticator, AuthenticatorFactory {
    private static final Logger logger = Logger.getLogger(org.keycloak.authentication.authenticators.resetcred.ResetCredentialChooseUser.class);
    public static final String PROVIDER_ID = "reset-credentials-attr-choose-user";

    public static final String ATTRIBUTE_KEY = "login.attribute.key";
    public static final String ATTRIBUTE_REGEX = "login.attribute.regex";

    public ResetCredentialAttributeChooseUser() {
    }

    @Override
    public void action(AuthenticationFlowContext context) {

        EventBuilder event = context.getEvent();
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String username = (String)formData.getFirst("username");

        if (username != null && !username.isEmpty()) {
            username = username.trim();
            RealmModel realm = context.getRealm();

            // Get user by username
            UserModel user = context.getSession().users().getUserByUsername(username, realm);

            // Get user by email
            if (user == null && realm.isLoginWithEmailAllowed() && username.contains("@")) {
                user = context.getSession().users().getUserByEmail(username, realm);
            }

            // Get user by attribute
            if (user == null) {
                user = this.getUserByAttribute(context, username);
            }

            context.getAuthenticationSession().setAuthNote("ATTEMPTED_USERNAME", username);

            if (user == null) {
                event.clone().detail("username", username).error("user_not_found");
                context.clearUser();
            } else if (!user.isEnabled()) {
                event.clone().detail("username", username).user(user).error("user_disabled");
                context.clearUser();
            } else {
                context.setUser(user);
            }

            context.success();
        } else {
            event.error("username_missing");
            Response challenge = context.form().setError("missingUsernameMessage", new Object[0]).createPasswordReset();
            context.failureChallenge(AuthenticationFlowError.INVALID_USER, challenge);
        }
    }

    private UserModel getUserByAttribute(AuthenticationFlowContext context, String userName) {
        AuthenticatorConfigModel authenticatorConfigModel = context.getAuthenticatorConfig();

        if (authenticatorConfigModel != null && authenticatorConfigModel.getConfig() != null && authenticatorConfigModel.getConfig().get(
            ATTRIBUTE_KEY) != null && authenticatorConfigModel.getConfig().get(ATTRIBUTE_REGEX) != null) {
            String attributeKey = authenticatorConfigModel.getConfig().get(ATTRIBUTE_KEY);
            String attributeRegex = authenticatorConfigModel.getConfig().get(ATTRIBUTE_REGEX);
            if (userName.matches(attributeRegex)) {
                List<UserModel> result = context.getSession().userStorageManager().searchForUserByUserAttribute(attributeKey, userName,
                    context.getRealm());
                if (result.size() == 1) {
                    return result.get(0);
                }
            }
        }
        return null;
    }

    @Override
    public String getDisplayType() {
        return "Attribute Choose User";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

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

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }
}

