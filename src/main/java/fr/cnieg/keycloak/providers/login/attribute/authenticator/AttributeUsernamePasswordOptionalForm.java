package fr.cnieg.keycloak.providers.login.attribute.authenticator;

import org.jboss.logging.Logger;
import java.util.Objects;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.broker.AbstractIdpAuthenticator;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.authentication.authenticators.util.AuthenticatorUtils;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.events.Errors;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import static org.keycloak.services.validation.Validation.FIELD_PASSWORD;

public final class AttributeUsernamePasswordOptionalForm extends AttributeUsernamePasswordForm {

    private static final Logger logger = Logger.getLogger(AttributeUsernamePasswordOptionalForm.class);


    public AttributeUsernamePasswordOptionalForm() {
        super();
    }

    public AttributeUsernamePasswordOptionalForm(KeycloakSession session) {
        super(session);
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        if (context.getUser() != null) {
            // We can skip the form when user is re-authenticating.
            context.success();
            return;
        }
        super.authenticate(context);
    }

    @Override
    public boolean validatePassword(AuthenticationFlowContext context, UserModel user, MultivaluedMap<String, String> inputData, boolean clearUser) {
        String password = inputData.getFirst(CredentialRepresentation.PASSWORD);
        if (password == null || password.isEmpty()) {
            return true;
        }

        if (isDisabledByBruteForce(context, user)) {
            return false;
        }

        if (user.credentialManager().isValid(UserCredentialModel.password(password))) {
            context.getAuthenticationSession().setAuthNote(AuthenticationManager.PASSWORD_VALIDATED, "true");
            return true;
        }

        return badPasswordHandler(context, user, clearUser);
    }

    @Override
    protected Response challenge(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        LoginFormsProvider forms = context.form();

        if (!formData.isEmpty()) forms.setFormData(formData);

        return forms.createLoginUsername();
    }

    @Override
    protected Response challenge(AuthenticationFlowContext context, String error, String field) {
        if (isConditionalPasskeysEnabled(context.getUser())) {
            // setup webauthn data when possible
            webauthnAuth.fillContextForm(context);
        }

        LoginFormsProvider form = context.form()
                .setExecution(context.getExecution().getId());

        AuthenticationSessionModel authenticationSession = context.getAuthenticationSession();

        if (Boolean.parseBoolean(authenticationSession.getAuthNote(USERNAME_HIDDEN))) {
            // if username is hidden, shown errors in the password field instead
            field = FIELD_PASSWORD;
        }

        if (error != null) {
            if (field != null) {
                form.addError(new FormMessage(field, error));
            } else {
                form.setError(error);
            }
        }

        if (context.getError() == AuthenticationFlowError.INVALID_CREDENTIALS) {
            return form.createLoginUsernamePassword();
        }

        return createLoginForm(form);
    }

    @Override
    protected Response createLoginForm(LoginFormsProvider form) {
        return form.createLoginUsername();
    }

    @Override
    protected String getDefaultChallengeMessage(AuthenticationFlowContext context) {
        if (context.getRealm().isLoginWithEmailAllowed())
            return Messages.INVALID_USERNAME_OR_EMAIL;
        return Messages.INVALID_USERNAME;
    }

    // Set up AuthenticationFlowContext error.
    private boolean badPasswordHandler(AuthenticationFlowContext context, UserModel user, boolean clearUser) {
        context.getEvent().user(user);
        context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);

        AuthenticatorUtils.setupReauthenticationInUsernamePasswordFormError(context);

        Response challengeResponse = challenge(context, Messages.INVALID_PASSWORD, FIELD_PASSWORD);
        context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challengeResponse);

        if (clearUser) {
            context.clearUser();
        }
        return true;
    }
}
