package fr.cnieg.keycloak.providers.login.attribute.authenticator;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.util.List;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;

public class AttributeUsernamePasswordForm extends UsernamePasswordForm implements Authenticator {
    public static final String ATTRIBUTE_KEY = "login.attribute.key";
    public static final String ATTRIBUTE_REGEX = "login.attribute.regex";

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
    public boolean validateUserAndPassword(AuthenticationFlowContext context, MultivaluedMap<String, String> inputData) {
        System.out.println("validateUserAndPassword()");
        context.clearUser();
        UserModel user = getUserOrAttribute(context, inputData);
        return user != null && validatePassword(context, user, inputData) && validateUser(context, user, inputData);
    }

    @Override
    public boolean validateUser(AuthenticationFlowContext context, MultivaluedMap<String, String> inputData) {
        System.out.println("validateUserAndPassword()");
        context.clearUser();
        UserModel user = getUserOrAttribute(context, inputData);
        return user != null && validateUser(context, user, inputData);
    }

    private boolean validateUser(AuthenticationFlowContext context, UserModel user, MultivaluedMap<String, String> inputData) {
        if (!enabledUser(context, user)) {
            return false;
        }
        String rememberMe = inputData.getFirst("rememberMe");
        boolean remember = rememberMe != null && rememberMe.equalsIgnoreCase("on");
        if (remember) {
            context.getAuthenticationSession().setAuthNote(Details.REMEMBER_ME, "true");
            context.getEvent().detail(Details.REMEMBER_ME, "true");
        } else {
            context.getAuthenticationSession().removeAuthNote(Details.REMEMBER_ME);
        }
        context.setUser(user);
        return true;
    }

    private UserModel getUserOrAttribute(AuthenticationFlowContext context, MultivaluedMap<String, String> inputData) {

        String userName = inputData.getFirst(AuthenticationManager.FORM_USERNAME);
        if (userName == null) {
            context.getEvent().error(Errors.USER_NOT_FOUND);
            Response challengeResponse = challenge(context, getDefaultChallengeMessage(context));
            context.failureChallenge(AuthenticationFlowError.INVALID_USER, challengeResponse);
            return null;
        }

        // remove leading and trailing whitespace
        userName = userName.trim();

        context.getEvent().detail(Details.USERNAME, userName);
        context.getAuthenticationSession().setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, userName);

        UserModel user;
        try {
            user = KeycloakModelUtils.findUserByNameOrEmail(context.getSession(), context.getRealm(), userName);
            if (user == null) {
                user = this.getUserByAttribute(context, userName);
            }
        } catch (ModelDuplicateException mde) {
            ServicesLogger.LOGGER.modelDuplicateException(mde);

            // Could happen during federation import
            if (mde.getDuplicateFieldName() != null && mde.getDuplicateFieldName().equals(UserModel.EMAIL)) {
                setDuplicateUserChallenge(context, Errors.EMAIL_IN_USE, Messages.EMAIL_EXISTS, AuthenticationFlowError.INVALID_USER);
            } else {
                setDuplicateUserChallenge(context, Errors.USERNAME_IN_USE, Messages.USERNAME_EXISTS, AuthenticationFlowError.INVALID_USER);
            }
            return null;
        }

        testInvalidUser(context, user);
        return user;
    }
}
