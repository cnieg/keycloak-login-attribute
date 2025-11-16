package fr.cnieg.keycloak.providers.login.attribute;

import com.microsoft.playwright.Browser;
import com.microsoft.playwright.BrowserContext;
import com.microsoft.playwright.Page;
import com.microsoft.playwright.Playwright;
import com.microsoft.playwright.options.AriaRole;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import io.restassured.common.mapper.TypeRef;
import io.restassured.http.ContentType;
import org.junit.jupiter.api.*;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.fail;

@Testcontainers
class KeycloakLoginAttributeProviderTest {
    @Container
    private static final KeycloakContainer KEYCLOAK_CONTAINER = new KeycloakContainer()
            .withAdminUsername("admin")
            .withAdminPassword("admin")
            .withDefaultProviderClasses()
            .withRealmImportFile("/testloginattribute-realm.json");
    private static Playwright playwright;
    private static Browser browser;
    private static KeycloakEventsClient eventsClient;
    BrowserContext context;
    Page page;

    @BeforeAll
    static void launchBrowser() {
        playwright = Playwright.create();
        browser = playwright.chromium().launch();
        eventsClient = new KeycloakEventsClient(KEYCLOAK_CONTAINER, "testloginattribute");
    }

    @AfterAll
    static void closeBrowser() {
        playwright.close();
    }

    @BeforeEach
    void createContextAndPage() {
        context = browser.newContext();
        page = context.newPage();
        eventsClient.clearEvents();
    }

    @AfterEach
    void closeContext() {
        context.close();
    }

    @Test
    void test_should_publish_login_event_for_jane_with_login_name() {
        // Given
        String username = "janedoe";
        String password = "s3cr3t";
        // When
        openAccountConsole();
        submitLoginForm(username, password);
        // Then
        KeycloakEvent loginEvent = eventsClient.awaitEvent(event -> "LOGIN".equals(event.type()));
        assertNull(loginEvent.error());
        assertEquals(username, loginEvent.details().get("username"));
    }

    @Test
    void test_should_publish_login_event_for_john_with_attribute() {
        // Given
        String attributeValueOfJohnDoe = "SHOULDBEOKFORLOGIN";
        String password = "s3cr3t";
        // When
        openAccountConsole();
        submitLoginForm(attributeValueOfJohnDoe, password);
        // Then
        KeycloakEvent loginEvent = eventsClient.awaitEvent(event -> "LOGIN".equals(event.type()));
        assertNull(loginEvent.error());
        assertEquals(attributeValueOfJohnDoe, loginEvent.details().get("username"));
    }

    @Test
    void test_should_publish_login_error_for_unknown_attribute() {
        // Given
        String attributeValueOfJaneDoe = "SHOULDBEkoFORLOGIN";
        String password = "s3cr3t";
        // When
        openAccountConsole();
        submitLoginForm(attributeValueOfJaneDoe, password);
        // Then
        KeycloakEvent loginError = eventsClient.awaitEvent(event -> "LOGIN_ERROR".equals(event.type())
                && "user_not_found".equals(event.error()));
        assertEquals(attributeValueOfJaneDoe, loginError.details().get("username"));
    }

    @Test
    void test_user_bill_should_be_locked_after_two_invalid_attempts_with_attribute() {
        // Given
        String attributeValueOfBillDoe = "SHOULDBEOKFORLOGINTOO";
        String invalidPassword = "fakes3cr3t";
        // When
        openAccountConsole();
        submitLoginForm(attributeValueOfBillDoe, invalidPassword);
        page.getByLabel("Password", new Page.GetByLabelOptions().setExact(true)).fill(invalidPassword);
        page.getByRole(AriaRole.BUTTON, new Page.GetByRoleOptions().setName("Sign In")).click();
        page.getByLabel("Password", new Page.GetByLabelOptions().setExact(true)).fill("s3cr3t");
        page.getByRole(AriaRole.BUTTON, new Page.GetByRoleOptions().setName("Sign In")).click();
        // Then
        KeycloakEvent lockEvent = eventsClient.awaitEvent(event -> "LOGIN_ERROR".equals(event.type())
                && "user_temporarily_disabled".equals(event.error()));
        assertEquals(attributeValueOfBillDoe, lockEvent.details().get("username"));
    }

    @Test
    void test_should_publish_reset_event_for_jane_with_login_name() {
        // Given
        String username = "janedoe";
        // When
        openForgotPasswordForm();
        submitResetForm(username);
        // Then
        KeycloakEvent resetEvent = eventsClient.awaitEvent(event -> "SEND_RESET_PASSWORD".equals(event.type())
                && event.error() == null);
        assertNull(resetEvent.error());
    }

    @Test
    void test_should_publish_reset_event_for_john_with_attribute() {
        // Given
        String attributeValueOfJohnDoe = "SHOULDBEOKFORLOGIN";
        // When
        openForgotPasswordForm();
        submitResetForm(attributeValueOfJohnDoe);
        // Then
        KeycloakEvent resetEvent = eventsClient.awaitEvent(event -> "SEND_RESET_PASSWORD".equals(event.type())
                && event.error() == null);
        assertNull(resetEvent.error());
    }

    @Test
    void test_should_publish_reset_error_for_unknown_attribute() {
        // Given
        String attributeValueOfJaneDoe = "SHOULDBEkoFORLOGIN";
        // When
        openForgotPasswordForm();
        submitResetForm(attributeValueOfJaneDoe);
        // Then
        KeycloakEvent resetError = eventsClient.awaitEvent(event -> "SEND_RESET_PASSWORD_ERROR".equals(event.type())
                && "user_not_found".equals(event.error()));
        assertEquals(attributeValueOfJaneDoe, resetError.details().get("username"));
    }

    private void openAccountConsole() {
        page.navigate(KEYCLOAK_CONTAINER.getAuthServerUrl() + "/realms/testloginattribute/account");
        page.getByRole(AriaRole.BUTTON, new Page.GetByRoleOptions().setName("Sign in")).click();
    }

    private void submitLoginForm(String username, String password) {
        page.getByLabel("Username").fill(username);
        page.getByLabel("Password", new Page.GetByLabelOptions().setExact(true)).fill(password);
        page.getByRole(AriaRole.BUTTON, new Page.GetByRoleOptions().setName("Sign In")).click();
    }

    private void openForgotPasswordForm() {
        openAccountConsole();
        page.getByRole(AriaRole.LINK, new Page.GetByRoleOptions().setName("Forgot Password?"))
                .click();
    }

    private void submitResetForm(String username) {
        page.getByLabel("Username").fill(username);
        page.getByRole(AriaRole.BUTTON, new Page.GetByRoleOptions().setName("Submit")).click();
    }

    private record KeycloakEvent(String type, String error, Map<String, String> details) {
    }

    private static class KeycloakEventsClient {
        private final String authServerUrl;
        private final String realm;
        private final String adminUsername;
        private final String adminPassword;

        KeycloakEventsClient(KeycloakContainer container, String realm) {
            this.authServerUrl = container.getAuthServerUrl();
            this.realm = realm;
            this.adminUsername = container.getAdminUsername();
            this.adminPassword = container.getAdminPassword();
        }

        void clearEvents() {
            given()
                    .auth().oauth2(adminAccessToken())
                    .delete(authServerUrl + "/admin/realms/" + realm + "/events")
                    .then()
                    .statusCode(204);
        }

        KeycloakEvent awaitEvent(Predicate<KeycloakEvent> predicate) {
            long deadline = System.currentTimeMillis() + Duration.ofSeconds(5).toMillis();
            while (System.currentTimeMillis() < deadline) {
                List<KeycloakEvent> events = events();
                for (KeycloakEvent event : events) {
                    if (predicate.test(event)) {
                        return event;
                    }
                }
                try {
                    Thread.sleep(200);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    fail("Interrupted while waiting for Keycloak event");
                }
            }
            fail("No Keycloak event matched predicate before timeout");
            return null;
        }

        private List<KeycloakEvent> events() {
            List<Map<String, Object>> rawEvents = given()
                    .auth().oauth2(adminAccessToken())
                    .get(authServerUrl + "/admin/realms/" + realm + "/events")
                    .then()
                    .statusCode(200)
                    .extract()
                    .as(new TypeRef<>() {
                    });
            return rawEvents.stream()
                    .map(this::toEvent)
                    .collect(Collectors.toList());
        }

        private KeycloakEvent toEvent(Map<String, Object> rawEvent) {
            String type = Objects.toString(rawEvent.get("type"), null);
            String error = Objects.toString(rawEvent.get("error"), null);
            Object details = rawEvent.getOrDefault("details", Collections.emptyMap());
            Map<String, String> stringDetails = Collections.emptyMap();
            if (details instanceof Map<?, ?> mapDetails) {
                stringDetails = mapDetails.entrySet().stream()
                        .collect(Collectors.toMap(entry -> Objects.toString(entry.getKey(), null),
                                entry -> Objects.toString(entry.getValue(), null)));
            }
            return new KeycloakEvent(type, error, stringDetails);
        }

        private String adminAccessToken() {
            return given()
                    .contentType(ContentType.URLENC)
                    .formParam("grant_type", "password")
                    .formParam("client_id", "admin-cli")
                    .formParam("username", adminUsername)
                    .formParam("password", adminPassword)
                    .post(authServerUrl + "/realms/master/protocol/openid-connect/token")
                    .then()
                    .statusCode(200)
                    .extract()
                    .path("access_token");
        }
    }
}
