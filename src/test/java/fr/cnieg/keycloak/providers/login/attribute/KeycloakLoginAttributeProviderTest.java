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
            .withRealmImportFile("/login-attribute-realm.json");
    static Playwright playwright;
    static Browser browser;
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
    void shouldIdentifyJaneWithLoginName() {
        page.navigate(KEYCLOAK_CONTAINER.getAuthServerUrl() + "/realms/testloginattribute/account");
        page.getByRole(AriaRole.BUTTON, new Page.GetByRoleOptions().setName("Sign in")).click();
        page.getByLabel("Username").fill("janedoe");
        page.getByLabel("Password").fill("s3cr3t");
        page.getByRole(AriaRole.BUTTON, new Page.GetByRoleOptions().setName("Sign In")).click();
        assertThat(page.locator("#landingLoggedInUser")).hasText("Anonymous");
    }

    @Test
    void shouldIdentifyJohnWithAttribute() {
        page.navigate(KEYCLOAK_CONTAINER.getAuthServerUrl() + "/realms/testloginattribute/account");
        page.getByRole(AriaRole.BUTTON, new Page.GetByRoleOptions().setName("Sign in")).click();
        page.getByLabel("Username").fill("SHOULDBEOKFORLOGIN");
        page.getByLabel("Password").fill("s3cr3t");
        page.getByRole(AriaRole.BUTTON, new Page.GetByRoleOptions().setName("Sign In")).click();
        assertThat(page.locator("#landingLoggedInUser")).hasText("Anonymous");
    }
    @Test
    void shouldNotIdentifyJaneWithAttribute() {
        page.navigate(KEYCLOAK_CONTAINER.getAuthServerUrl() + "/realms/testloginattribute/account");
        page.getByRole(AriaRole.BUTTON, new Page.GetByRoleOptions().setName("Sign in")).click();
        page.getByLabel("Username").fill("SHOULDBEkoFORLOGIN");
        page.getByLabel("Password").fill("s3cr3t");
        page.getByRole(AriaRole.BUTTON, new Page.GetByRoleOptions().setName("Sign In")).click();
        assertThat(page.getByText("Invalid username or password.")).isVisible();

    }
    @Test
    void shouldResetJaneWithLoginName() {
        page.navigate(KEYCLOAK_CONTAINER.getAuthServerUrl() + "/realms/testloginattribute/account");
        page.getByRole(AriaRole.BUTTON, new Page.GetByRoleOptions().setName("Sign in")).click();
        page.getByRole(AriaRole.LINK, new Page.GetByRoleOptions().setName("Forgot Password?")).click();
        page.getByLabel("Username").fill("janedoe");
        page.getByRole(AriaRole.BUTTON, new Page.GetByRoleOptions().setName("Submit")).click();
        assertThat(page.getByText("Failed to send email, please try again later.")).isVisible();
    }

    @Test
    void shouldResetJohnWithAttribute() {
        page.navigate(KEYCLOAK_CONTAINER.getAuthServerUrl() + "/realms/testloginattribute/account");
        page.getByRole(AriaRole.BUTTON, new Page.GetByRoleOptions().setName("Sign in")).click();
        page.getByRole(AriaRole.LINK, new Page.GetByRoleOptions().setName("Forgot Password?")).click();
        page.getByLabel("Username").fill("SHOULDBEOKFORLOGIN");
        page.getByRole(AriaRole.BUTTON, new Page.GetByRoleOptions().setName("Submit")).click();
        assertThat(page.getByText("Failed to send email, please try again later.")).isVisible();
    }
    @Test
    void shouldNotResetJaneWithAttribute() {
        page.navigate(KEYCLOAK_CONTAINER.getAuthServerUrl() + "/realms/testloginattribute/account");
        page.getByRole(AriaRole.BUTTON, new Page.GetByRoleOptions().setName("Sign in")).click();
        page.getByRole(AriaRole.LINK, new Page.GetByRoleOptions().setName("Forgot Password?")).click();
        page.getByLabel("Username").fill("SHOULDBEkoFORLOGIN");
        page.getByRole(AriaRole.BUTTON, new Page.GetByRoleOptions().setName("Submit")).click();
        assertThat(page.getByText("You should receive an email shortly with further instructions.")).isVisible();
    }
}