package fr.cnieg.keycloak.providers.login.attribute;

import com.microsoft.playwright.Browser;
import com.microsoft.playwright.BrowserContext;
import com.microsoft.playwright.Page;
import com.microsoft.playwright.Playwright;
import com.microsoft.playwright.options.AriaRole;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.junit.jupiter.api.*;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static com.microsoft.playwright.assertions.PlaywrightAssertions.assertThat;

@Testcontainers
class KeycloakLoginAttributeProviderTest {
    @Container
    private static final KeycloakContainer KEYCLOAK_CONTAINER = new KeycloakContainer()
            .withProviderClassesFrom("target/classes")
            .WithPortBinding(9000, true)
            .WithWaitStrategy(Wait.ForUnixContainer().UntilHttpRequestIsSucceeded(request => request.ForPath("/health/ready").ForPort(9000)))
            .withRealmImportFile("/login-attribute-realm.json");
    private static Playwright playwright;
    private static Browser browser;
    BrowserContext context;
    Page page;

    @BeforeAll
    static void launchBrowser() {
        playwright = Playwright.create();
        browser = playwright.chromium().launch();
    }

    @AfterAll
    static void closeBrowser() {
        playwright.close();
    }

    @BeforeEach
    void createContextAndPage() {
        context = browser.newContext();
        page = context.newPage();
    }

    @AfterEach
    void closeContext() {
        context.close();
    }

    @Test
    void test_should_identify_jane_with_Login_name() {
        // Given
        String username = "janedoe";
        String password = "s3cr3t";
        String expected = username;
        // When
        page.navigate(KEYCLOAK_CONTAINER.getAuthServerUrl() + "/realms/testloginattribute/account");
        page.getByRole(AriaRole.BUTTON, new Page.GetByRoleOptions().setName("Sign in")).click();
        page.getByLabel("Username").fill(username);
        page.getByLabel("Password", new Page.GetByLabelOptions().setExact(true)).fill(password);
        page.getByRole(AriaRole.BUTTON, new Page.GetByRoleOptions().setName("Sign In")).click();
        // Then
        assertThat(page.getByRole(AriaRole.TEXTBOX, new Page.GetByRoleOptions().setName("username"))).hasValue(expected);
    }

    @Test
    void test_should_identify_john_with_attribute() {
        // Given
        String attributeValueOfJohnDoe = "SHOULDBEOKFORLOGIN";
        String password = "s3cr3t";
        String expected = "johndoe";
        // When
        page.navigate(KEYCLOAK_CONTAINER.getAuthServerUrl() + "/realms/testloginattribute/account");
        page.getByRole(AriaRole.BUTTON, new Page.GetByRoleOptions().setName("Sign in")).click();
        page.getByLabel("Username").fill(attributeValueOfJohnDoe);
        page.getByLabel("Password", new Page.GetByLabelOptions().setExact(true)).fill(password);
        page.getByRole(AriaRole.BUTTON, new Page.GetByRoleOptions().setName("Sign In")).click();
        // Then
        assertThat(page.getByRole(AriaRole.TEXTBOX, new Page.GetByRoleOptions().setName("username"))).hasValue(expected);
    }

    @Test
    void test_should_not_identify_jane_with_attribute() {
        // Given
        String attributeValueOfJaneDoe = "SHOULDBEkoFORLOGIN";
        String password = "s3cr3t";
        String expected = "Invalid username or password.";
        // When
        page.navigate(KEYCLOAK_CONTAINER.getAuthServerUrl() + "/realms/testloginattribute/account");
        page.getByRole(AriaRole.BUTTON, new Page.GetByRoleOptions().setName("Sign in")).click();
        page.getByLabel("Username").fill(attributeValueOfJaneDoe);
        page.getByLabel("Password", new Page.GetByLabelOptions().setExact(true)).fill(password);
        page.getByRole(AriaRole.BUTTON, new Page.GetByRoleOptions().setName("Sign In")).click();
        // Then
        assertThat(page.getByText(expected)).isVisible();
    }

    @Test
    void test_should_reset_jane_with_login_name() {
        // Given
        String username = "janedoe";
        String expected = "Failed to send email, please try again later.";
        // When
        page.navigate(KEYCLOAK_CONTAINER.getAuthServerUrl() + "/realms/testloginattribute/account");
        page.getByRole(AriaRole.BUTTON, new Page.GetByRoleOptions().setName("Sign in")).click();
        page.getByRole(AriaRole.LINK, new Page.GetByRoleOptions().setName("Forgot Password?")).click();
        page.getByLabel("Username").fill(username);
        page.getByRole(AriaRole.BUTTON, new Page.GetByRoleOptions().setName("Submit")).click();
        // Then
        assertThat(page.getByText(expected)).isVisible();
    }

    @Test
    void test_should_reset_john_with_attribute() {
        // Given
        String attributeValueOfJohnDoe = "SHOULDBEOKFORLOGIN";
        String expected = "Failed to send email, please try again later.";
        // When
        page.navigate(KEYCLOAK_CONTAINER.getAuthServerUrl() + "/realms/testloginattribute/account");
        page.getByRole(AriaRole.BUTTON, new Page.GetByRoleOptions().setName("Sign in")).click();
        page.getByRole(AriaRole.LINK, new Page.GetByRoleOptions().setName("Forgot Password?")).click();
        page.getByLabel("Username").fill(attributeValueOfJohnDoe);
        page.getByRole(AriaRole.BUTTON, new Page.GetByRoleOptions().setName("Submit")).click();
        // Then
        assertThat(page.getByText(expected)).isVisible();
    }

    @Test
    void test_should_not_reset_jane_with_attribute() {
        // Given
        String attributeValueOfJaneDoe = "SHOULDBEkoFORLOGIN";
        String expected = "You should receive an email shortly with further instructions.";
        // When
        page.navigate(KEYCLOAK_CONTAINER.getAuthServerUrl() + "/realms/testloginattribute/account");
        page.getByRole(AriaRole.BUTTON, new Page.GetByRoleOptions().setName("Sign in")).click();
        page.getByRole(AriaRole.LINK, new Page.GetByRoleOptions().setName("Forgot Password?")).click();
        page.getByLabel("Username").fill(attributeValueOfJaneDoe);
        page.getByRole(AriaRole.BUTTON, new Page.GetByRoleOptions().setName("Submit")).click();
        // Then
        assertThat(page.getByText(expected)).isVisible();
    }
}
