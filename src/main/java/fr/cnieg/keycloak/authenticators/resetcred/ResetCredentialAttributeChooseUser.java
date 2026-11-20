package fr.cnieg.keycloak.authenticators.resetcred;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.authentication.authenticators.resetcred.ResetCredentialChooseUser;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.List;

import static fr.cnieg.keycloak.AuthenticatorUserModel.getUserModel;

/**
 *
 */
public class ResetCredentialAttributeChooseUser extends ResetCredentialChooseUser {
    /**
     *
     */
    public static final String PROVIDER_ID = "reset-credentials-attr-choose-user";
    /**
     * Attribute key used for check identity
     */
    public static final String ATTRIBUTE_KEY = "login.attribute.key";
    /**
     * Attribute format
     */
    public static final String ATTRIBUTE_REGEX = "login.attribute.regex";

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
        String username = formData.getFirst("username");
        if (username == null || username.isEmpty()) {
            event.error(Errors.USERNAME_MISSING);
            Response challenge = context.form()
                    .addError(new FormMessage(Validation.FIELD_USERNAME, Messages.MISSING_USERNAME))
                    .createPasswordReset();
            context.failureChallenge(AuthenticationFlowError.INVALID_USER, challenge);
            return;
        }

        username = username.trim();

        RealmModel realm = context.getRealm();
        UserModel user = context.getSession().users().getUserByUsername(realm, username);
        if (user == null && realm.isLoginWithEmailAllowed() && username.contains("@")) {
            user =  context.getSession().users().getUserByEmail(realm, username);
        }
        // Get user by attribute
        if (user == null) {
            user = this.getUserByAttribute(context, username);
        }

        context.getAuthenticationSession().setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, username);

        // we don't want people guessing usernames, so if there is a problem, just continue, but don't set the user
        // a null user will notify further executions, that this was a failure.
        if (user == null) {
            event.clone()
                    .detail(Details.USERNAME, username)
                    .error(Errors.USER_NOT_FOUND);
            context.clearUser();
        } else if (!user.isEnabled()) {
            event.clone()
                    .detail(Details.USERNAME, username)
                    .user(user).error(Errors.USER_DISABLED);
            context.clearUser();
        } else {
            context.setUser(user);
        }

        context.success();
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
        providerConfigProperty.setName(ResetCredentialAttributeChooseUser.ATTRIBUTE_KEY);
        providerConfigProperty.setLabel("User Attribute");
        providerConfigProperty.setType(ProviderConfigProperty.STRING_TYPE);
        providerConfigProperty.setHelpText("User attribute that can be used as an alternative identifier ");
        CONFIG_PROPERTIES.add(providerConfigProperty);
        providerConfigProperty = new ProviderConfigProperty();
        providerConfigProperty.setName(ResetCredentialAttributeChooseUser.ATTRIBUTE_REGEX);
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

