package fr.cnieg.keycloak.providers.login.attribute.authenticator;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.browser.PasswordForm;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.managers.AuthenticationManager;

public class PasswordOnceForm extends PasswordForm {

    public PasswordOnceForm(KeycloakSession session) {
        super(session);
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        String passwordValidated = context.getAuthenticationSession().getAuthNote(AuthenticationManager.PASSWORD_VALIDATED);
        if (Boolean.parseBoolean(passwordValidated)) {
            context.success();
            return;
        }

        super.authenticate(context);
    }
}
