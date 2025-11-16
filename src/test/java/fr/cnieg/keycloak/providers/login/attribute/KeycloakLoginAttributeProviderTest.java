package fr.cnieg.keycloak.providers.login.attribute;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import io.restassured.common.mapper.TypeRef;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.junit.jupiter.api.*;
import org.subethamail.wiser.Wiser;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Duration;
import java.util.HashMap;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Predicate;
import java.util.UUID;
import java.util.stream.Collectors;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;

@Testcontainers
class KeycloakLoginAttributeProviderTest {
    private static final int SMTP_PORT = 2525;
    private static final String REALM = "testloginattribute";
    private static final String CLIENT_ID = "account-console";

    static {
        org.testcontainers.Testcontainers.exposeHostPorts(SMTP_PORT);
    }

    @Container
    private static final KeycloakContainer KEYCLOAK_CONTAINER = new KeycloakContainer()
            .withAdminUsername("admin")
            .withAdminPassword("admin")
            .withDefaultProviderClasses()
            .withRealmImportFile("/testloginattribute-realm.json");
    private static KeycloakEventsClient eventsClient;
    private static Wiser smtpServer;

    @BeforeAll
    static void startInfrastructure() {
        smtpServer = new Wiser();
        smtpServer.setPort(SMTP_PORT);
        smtpServer.start();
        eventsClient = new KeycloakEventsClient(KEYCLOAK_CONTAINER, REALM);
    }

    @AfterAll
    static void stopInfrastructure() {
        smtpServer.stop();
    }

    @BeforeEach
    void clearEvents() {
        eventsClient.clearEvents();
    }

    @Test
    void test_should_publish_login_event_for_jane_with_login_name() {
        // Given
        String username = "janedoe";
        String password = "s3cr3t";
        // When
        HttpSession session = new HttpSession();
        LoginForm loginForm = loadLoginForm(session);
        submitLoginForm(session, loginForm, username, password);
        // Then
        KeycloakEvent loginEvent = awaitLoginEvent(username);
        assertNull(loginEvent.error());
        assertEquals(username, loginEvent.details().get("username"));
    }

    @Test
    void test_should_publish_login_event_for_john_with_attribute() {
        // Given
        String attributeValueOfJohnDoe = "SHOULDBEOKFORLOGIN";
        String password = "s3cr3t";
        // When
        HttpSession session = new HttpSession();
        LoginForm loginForm = loadLoginForm(session);
        submitLoginForm(session, loginForm, attributeValueOfJohnDoe, password);
        // Then
        KeycloakEvent loginEvent = awaitLoginEvent(attributeValueOfJohnDoe, "johndoe");
        assertNull(loginEvent.error());
        assertEquals("johndoe", loginEvent.details().get("username"));
    }

    @Test
    void test_should_publish_login_error_for_unknown_attribute() {
        // Given
        String attributeValueOfJaneDoe = "SHOULDBEkoFORLOGIN";
        String password = "s3cr3t";
        // When
        HttpSession session = new HttpSession();
        LoginForm loginForm = loadLoginForm(session);
        submitLoginForm(session, loginForm, attributeValueOfJaneDoe, password);
        // Then
        KeycloakEvent loginError = awaitLoginErrorEvent(attributeValueOfJaneDoe, "user_not_found");
        assertEquals(attributeValueOfJaneDoe, loginError.details().get("username"));
    }

    @Test
    void test_user_bill_should_be_locked_after_two_invalid_attempts_with_attribute() {
        // Given
        String attributeValueOfBillDoe = "SHOULDBEOKFORLOGINTOO";
        String invalidPassword = "fakes3cr3t";
        // When
        HttpSession session = new HttpSession();
        LoginForm loginForm = loadLoginForm(session);
        loginForm = submitLoginForm(session, loginForm, attributeValueOfBillDoe, invalidPassword);
        assertNotNull(loginForm, "Expected to remain on login form after invalid password");
        loginForm = submitLoginForm(session, loginForm, attributeValueOfBillDoe, invalidPassword);
        assertNotNull(loginForm, "Expected to remain on login form after second invalid password");
        submitLoginForm(session, loginForm, attributeValueOfBillDoe, "s3cr3t");
        // Then
        KeycloakEvent lockEvent = awaitLoginErrorEvent(attributeValueOfBillDoe, "user_temporarily_disabled");
        assertEquals(attributeValueOfBillDoe, lockEvent.details().get("username"));
    }

    @Test
    void test_should_publish_reset_event_for_jane_with_login_name() {
        // Given
        String username = "janedoe";
        // When
        HttpSession session = new HttpSession();
        LoginForm loginForm = loadLoginForm(session);
        ResetPasswordForm resetForm = loadResetPasswordForm(session, loginForm.resetPasswordUrl());
        submitResetForm(session, resetForm, username);
        // Then
        KeycloakEvent resetEvent = awaitResetPasswordEvent(username);
        assertNull(resetEvent.error());
    }

    @Test
    void test_should_publish_reset_event_for_john_with_attribute() {
        // Given
        String attributeValueOfJohnDoe = "SHOULDBEOKFORLOGIN";
        // When
        HttpSession session = new HttpSession();
        LoginForm loginForm = loadLoginForm(session);
        ResetPasswordForm resetForm = loadResetPasswordForm(session, loginForm.resetPasswordUrl());
        submitResetForm(session, resetForm, attributeValueOfJohnDoe);
        // Then
        KeycloakEvent resetEvent = awaitResetPasswordEvent(attributeValueOfJohnDoe, "johndoe");
        assertNull(resetEvent.error());
    }

    @Test
    void test_should_publish_reset_error_for_unknown_attribute() {
        // Given
        String attributeValueOfJaneDoe = "SHOULDBEkoFORLOGIN";
        // When
        HttpSession session = new HttpSession();
        LoginForm loginForm = loadLoginForm(session);
        ResetPasswordForm resetForm = loadResetPasswordForm(session, loginForm.resetPasswordUrl());
        submitResetForm(session, resetForm, attributeValueOfJaneDoe);
        // Then
        KeycloakEvent resetError = awaitResetPasswordErrorEvent(attributeValueOfJaneDoe, "user_not_found");
        assertEquals(attributeValueOfJaneDoe, resetError.details().get("username"));
    }

    private KeycloakEvent awaitLoginEvent(String... usernames) {
        return eventsClient.awaitEvent(event -> isLoginEvent(event)
                && event.error() == null
                && matchesUsernamesIfPresent(event, usernames));
    }

    private KeycloakEvent awaitLoginErrorEvent(String username, String expectedError) {
        return eventsClient.awaitEvent(event -> isLoginEvent(event)
                && Objects.equals(expectedError, event.error())
                && Objects.equals(username, event.details().get("username")));
    }

    private KeycloakEvent awaitResetPasswordEvent(String... usernames) {
        return eventsClient.awaitEvent(Duration.ofSeconds(20), event -> isResetPasswordEvent(event)
                && isSuccessfulResetEvent(event)
                && matchesUsernamesIfPresent(event, usernames));
    }

    private boolean isSuccessfulResetEvent(KeycloakEvent event) {
        String error = event.error();
        if (error == null) {
            return true;
        }
        return Objects.equals("email_send_failed", error) || Objects.equals("email_not_sent", error);
    }

    private KeycloakEvent awaitResetPasswordErrorEvent(String username, String expectedError) {
        return eventsClient.awaitEvent(event -> isResetPasswordEvent(event)
                && Objects.equals(expectedError, event.error())
                && Objects.equals(username, event.details().get("username")));
    }

    private boolean isResetPasswordEvent(KeycloakEvent event) {
        return switch (event.type()) {
            case "SEND_RESET_PASSWORD", "RESET_PASSWORD", "SEND_RESET_PASSWORD_ERROR", "RESET_PASSWORD_ERROR" -> true;
            default -> false;
        };
    }

    private boolean isLoginEvent(KeycloakEvent event) {
        return "LOGIN".equals(event.type()) || "LOGIN_ERROR".equals(event.type());
    }

    private boolean matchesUsernamesIfPresent(KeycloakEvent event, String... usernames) {
        String detailUsername = event.details().get("username");
        if (detailUsername == null) {
            return true;
        }
        if (usernames == null || usernames.length == 0) {
            return false;
        }
        for (String username : usernames) {
            if (username != null && Objects.equals(detailUsername, username)) {
                return true;
            }
        }
        return false;
    }

    private LoginForm loadLoginForm(HttpSession session) {
        Response response = session.get(authorizationEndpoint(), Map.of(
                "client_id", CLIENT_ID,
                "redirect_uri", accountRedirectUri(),
                "response_type", "code",
                "scope", "openid",
                "state", UUID.randomUUID().toString(),
                "nonce", UUID.randomUUID().toString()
        ));
        response = followRedirectsIfNeeded(session, response);
        assertEquals(200, response.statusCode(), "Unable to load login page");
        return LoginForm.parse(response.getBody().asString());
    }

    private LoginForm submitLoginForm(HttpSession session, LoginForm form, String username, String password) {
        Response response = session.postForm(form.action(), Map.of(
                "username", username,
                "password", password,
                "credentialId", form.credentialId()
        ));
        if (response.statusCode() == 200) {
            return LoginForm.parse(response.getBody().asString());
        }
        if (response.statusCode() == 302 || response.statusCode() == 303) {
            return null;
        }
        fail("Unexpected status code when submitting login form: " + response.statusCode());
        return null;
    }

    private ResetPasswordForm loadResetPasswordForm(HttpSession session, String url) {
        Response response = session.get(url, Collections.emptyMap());
        response = followRedirectsIfNeeded(session, response);
        assertEquals(200, response.statusCode(), "Unable to load reset password form");
        return ResetPasswordForm.parse(response.getBody().asString());
    }

    private void submitResetForm(HttpSession session, ResetPasswordForm form, String username) {
        Response response = session.postForm(form.action(), Map.of("username", username));
        if (response.statusCode() == 200 || response.statusCode() == 302) {
            return;
        }
        fail("Unexpected status code when submitting reset password form: " + response.statusCode());
    }

    private String authorizationEndpoint() {
        return KEYCLOAK_CONTAINER.getAuthServerUrl() + "/realms/" + REALM + "/protocol/openid-connect/auth";
    }

    private String accountRedirectUri() {
        return KEYCLOAK_CONTAINER.getAuthServerUrl() + "/realms/" + REALM + "/account/";
    }

    private static String toAbsoluteUrl(String url) {
        if (url == null || url.isBlank()) {
            return url;
        }
        if (url.startsWith("http://") || url.startsWith("https://")) {
            return url;
        }
        if (!url.startsWith("/")) {
            url = "/" + url;
        }
        return KEYCLOAK_CONTAINER.getAuthServerUrl() + url;
    }

    private Response followRedirectsIfNeeded(HttpSession session, Response response) {
        Response current = response;
        int redirectCount = 0;
        while (current != null && isRedirect(current.statusCode())) {
            String location = current.getHeader("Location");
            assertNotNull(location, "Redirect response missing Location header");
            current = session.get(toAbsoluteUrl(location), Collections.emptyMap());
            redirectCount++;
            if (redirectCount > 10) {
                fail("Too many redirects when loading form");
            }
        }
        return current;
    }

    private boolean isRedirect(int statusCode) {
        return statusCode == 301 || statusCode == 302 || statusCode == 303 || statusCode == 307 || statusCode == 308;
    }

    private record KeycloakEvent(String type, String error, Map<String, String> details) {
    }

    private record LoginForm(String action, String resetPasswordUrl, String credentialId) {
        static LoginForm parse(String html) {
            Document document = Jsoup.parse(html);
            Element form = document.getElementById("kc-form-login");
            if (form == null) {
                fail("Login form not found in response");
            }
            Element resetLink = document.getElementById("kc-reset-password");
            if (resetLink == null) {
                fail("Reset password link not found in login page");
            }
            Element credentialInput = form.selectFirst("input[name=credentialId]");
            String credentialId = credentialInput != null ? credentialInput.attr("value") : "";
            return new LoginForm(
                    toAbsoluteUrl(form.attr("action")),
                    toAbsoluteUrl(resetLink.attr("href")),
                    credentialId
            );
        }
    }

    private record ResetPasswordForm(String action) {
        static ResetPasswordForm parse(String html) {
            Document document = Jsoup.parse(html);
            Element form = document.getElementById("kc-reset-password-form");
            if (form == null) {
                fail("Reset password form not found in response");
            }
            return new ResetPasswordForm(toAbsoluteUrl(form.attr("action")));
        }
    }

    private static class HttpSession {
        private final Map<String, String> cookies = new HashMap<>();

        Response get(String url, Map<String, ?> queryParams) {
            RequestSpecification specification = given()
                    .redirects().follow(false)
                    .cookies(cookies);
            if (queryParams != null && !queryParams.isEmpty()) {
                specification.queryParams(queryParams);
            }
            Response response = specification.get(url);
            cookies.putAll(response.getCookies());
            return response;
        }

        Response postForm(String url, Map<String, ?> formParams) {
            RequestSpecification specification = given()
                    .redirects().follow(false)
                    .cookies(cookies)
                    .contentType(ContentType.URLENC);
            if (formParams != null && !formParams.isEmpty()) {
                specification.formParams(formParams);
            }
            Response response = specification.post(url);
            cookies.putAll(response.getCookies());
            return response;
        }
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
            return awaitEvent(Duration.ofSeconds(5), predicate);
        }

        KeycloakEvent awaitEvent(Duration timeout, Predicate<KeycloakEvent> predicate) {
            long deadline = System.currentTimeMillis() + timeout.toMillis();
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
