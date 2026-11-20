package fr.cnieg.keycloak.providers.login.attribute.authenticator;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;

import static fr.cnieg.keycloak.AuthenticatorUserModel.getUserModel;
import static org.keycloak.services.validation.Validation.FIELD_USERNAME;

/**
 * Attribute username password form
 */
public class AttributeUsernamePasswordForm extends UsernamePasswordForm {
    /**
     * Attribute key used for check identity
     */
    public static final String ATTRIBUTE_KEY = "login.attribute.key";
    /**
     * Attribute format
     */
    public static final String ATTRIBUTE_REGEX = "login.attribute.regex";

    public AttributeUsernamePasswordForm() {
        super();
    }

    public AttributeUsernamePasswordForm(KeycloakSession session) {
        super(session);
    }

    private UserModel getUserByAttribute(AuthenticationFlowContext context, String userName) {
        return getUserModel(context, userName, ATTRIBUTE_KEY, ATTRIBUTE_REGEX);
    }

    /**
     * @param context   Authentication Flow context
     * @param inputData User inputs
     * @return password checked
     */
    @Override
    public boolean validateUserAndPassword(AuthenticationFlowContext context, MultivaluedMap<String, String> inputData) {
        UserModel user = getAttributeUser(context, inputData);
        boolean shouldClearUserFromCtxAfterBadPassword = !isUserAlreadySetBeforeUsernamePasswordAuth(context);
        return user != null && validatePassword(context, user, inputData, shouldClearUserFromCtxAfterBadPassword) && validateUser(context, user, inputData);
    }

    /**
     * @param context   Authentication Flow context
     * @param inputData User inputs
     * @return password checked
     */
    @Override
    public boolean validateUser(AuthenticationFlowContext context, MultivaluedMap<String, String> inputData) {
        UserModel user = getAttributeUser(context, inputData);
        return user != null && validateUser(context, user, inputData);
    }

    protected boolean validateUser(AuthenticationFlowContext context, UserModel user, MultivaluedMap<String, String> inputData) {
        if (!enabledUser(context, user)) {
            return false;
        }
        String rememberMe = inputData.getFirst("rememberMe");
        boolean remember = context.getRealm().isRememberMe() && rememberMe != null && rememberMe.equalsIgnoreCase("on");
        if (remember) {
            context.getAuthenticationSession().setAuthNote(Details.REMEMBER_ME, "true");
            context.getEvent().detail(Details.REMEMBER_ME, "true");
        } else {
            context.getAuthenticationSession().removeAuthNote(Details.REMEMBER_ME);
        }
        context.setUser(user);
        return true;
    }

    protected UserModel getAttributeUser(AuthenticationFlowContext context, MultivaluedMap<String, String> inputData) {
        if (isUserAlreadySetBeforeUsernamePasswordAuth(context)) {
            // Get user from the authentication context in case he was already set before this authenticator
            UserModel user = context.getUser();
            testInvalidUser(context, user);
            return user;
        } else {
            // Normal login. In this case this authenticator is supposed to establish identity of the user from the provided username
            context.clearUser();
            return getAttributeUserFromForm(context, inputData);
        }
    }

    protected UserModel getAttributeUserFromForm(AuthenticationFlowContext context, MultivaluedMap<String, String> inputData) {
        String username = inputData.getFirst(AuthenticationManager.FORM_USERNAME);
        if (username == null || username.isEmpty()) {
            context.getEvent().error(Errors.USER_NOT_FOUND);
            Response challengeResponse = challenge(context, getDefaultChallengeMessage(context), FIELD_USERNAME);
            context.failureChallenge(AuthenticationFlowError.INVALID_USER, challengeResponse);
            return null;
        }

        // remove leading and trailing whitespace
        username = username.trim();

        context.getEvent().detail(Details.USERNAME, username);
        context.getAuthenticationSession().setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, username);

        UserModel user = null;
        try {
            user = KeycloakModelUtils.findUserByNameOrEmail(context.getSession(), context.getRealm(), username);
            if (user == null) {
                user = this.getUserByAttribute(context, username);
                if(user != null) {
                    context.getAuthenticationSession().setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, user.getUsername());
                }
            }
        } catch (ModelDuplicateException mde) {
            ServicesLogger.LOGGER.modelDuplicateException(mde);

            // Could happen during federation import
            if (mde.getDuplicateFieldName() != null && mde.getDuplicateFieldName().equals(UserModel.EMAIL)) {
                setDuplicateUserChallenge(context, Errors.EMAIL_IN_USE, Messages.EMAIL_EXISTS, AuthenticationFlowError.INVALID_USER);
            } else {
                setDuplicateUserChallenge(context, Errors.USERNAME_IN_USE, Messages.USERNAME_EXISTS, AuthenticationFlowError.INVALID_USER);
            }
            return user;
        }

        testInvalidUser(context, user);
        return user;
    }
}
