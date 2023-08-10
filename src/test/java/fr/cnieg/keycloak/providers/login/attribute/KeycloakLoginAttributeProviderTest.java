package fr.cnieg.keycloak.providers.login.attribute;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.junit.jupiter.api.Test;

class KeycloakLoginAttributeProviderTest {
    @Test
    public void shouldStartKeycloakWithExtensionClassFolder() {
        try (KeycloakContainer keycloak = new KeycloakContainer()
                .withProviderClassesFrom("target/classes")) {
            keycloak.start();
        }
    }
}