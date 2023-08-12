package fr.cnieg.keycloak.providers.login.attribute;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.junit.jupiter.api.Test;

class KeycloakLoginAttributeProviderTest {
    @Test
    void shouldStartKeycloakWithExtensionClassFolder() {
        try (KeycloakContainer keycloak = new KeycloakContainer()
                .withProviderClassesFrom("target/classes")
                .withRealmImportFile("/login-attribute-realm.json")) {
            keycloak.start();
        }
    }
}