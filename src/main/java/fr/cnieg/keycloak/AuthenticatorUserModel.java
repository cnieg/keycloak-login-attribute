package fr.cnieg.keycloak;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.UserModel;

import java.util.List;
import java.util.stream.Collectors;

public class AuthenticatorUserModel {

    private AuthenticatorUserModel() {
        throw new IllegalStateException("Utility class");
    }

    public static UserModel getUserModel(AuthenticationFlowContext context, String userName, String attributeKey2, String attributeRegex2) {
        AuthenticatorConfigModel authenticatorConfigModel = context.getAuthenticatorConfig();

        if (authenticatorConfigModel != null && authenticatorConfigModel.getConfig() != null && authenticatorConfigModel.getConfig().get(
                attributeKey2) != null && authenticatorConfigModel.getConfig().get(attributeRegex2) != null) {
            String attributeKey = authenticatorConfigModel.getConfig().get(attributeKey2);
            String attributeRegex = authenticatorConfigModel.getConfig().get(attributeRegex2);
            if (userName.matches(attributeRegex)) {
                List<UserModel> result = context.getSession().users()
                        .searchForUserByUserAttributeStream(context.getRealm(), attributeKey, userName)
                        .collect(Collectors.toList());
                if (result.size() == 1) {
                    return result.get(0);
                }
            }
        }
        return null;
    }
}
