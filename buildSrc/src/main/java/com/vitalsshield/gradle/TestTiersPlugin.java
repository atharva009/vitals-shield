package com.vitalsshield.gradle;

import java.util.Set;
import org.gradle.api.Plugin;
import org.gradle.api.Project;
import org.gradle.api.artifacts.MinimalExternalModuleDependency;
import org.gradle.api.artifacts.VersionCatalog;
import org.gradle.api.artifacts.VersionCatalogsExtension;
import org.gradle.api.artifacts.dsl.DependencyHandler;
import org.gradle.api.plugins.JavaPlugin;
import org.gradle.api.plugins.JavaPluginExtension;
import org.gradle.api.provider.Provider;
import org.gradle.api.tasks.SourceSet;
import org.gradle.api.tasks.SourceSetContainer;
import org.gradle.api.tasks.testing.Test;
import org.gradle.api.tasks.testing.logging.TestExceptionFormat;
import org.gradle.api.tasks.testing.logging.TestLogEvent;
import org.gradle.jvm.toolchain.JavaLanguageVersion;

/**
 * Shared Java module conventions, applied as {@code vitalsshield.test-tiers}:
 * Java 21 toolchain, Maven Central, JUnit 5 + AssertJ (versions from the Spring Boot BOM),
 * and the four JUnit-tag test tiers.
 *
 * <ul>
 *   <li>{@code test}: everything except tags {@code integration}, {@code e2e}, {@code drill}</li>
 *   <li>{@code integrationTest}, {@code e2eTest}, {@code drillTest}: exactly one tag each</li>
 * </ul>
 */
public class TestTiersPlugin implements Plugin<Project> {

    private static final String[] HEAVY_TAGS = {"integration", "e2e", "drill"};

    /** Tiers that legitimately run zero tests in Phase 0; Gradle 9 otherwise fails them. */
    private static final Set<String> MAY_BE_EMPTY = Set.of("e2eTest", "drillTest");

    @Override
    public void apply(Project project) {
        project.getPluginManager().apply(JavaPlugin.class);

        project.getExtensions().getByType(JavaPluginExtension.class)
                .getToolchain().getLanguageVersion().set(JavaLanguageVersion.of(21));

        project.getRepositories().mavenCentral();

        addTestDependencies(project);

        project.getTasks().named("test", Test.class, test ->
                test.useJUnitPlatform(junit -> junit.excludeTags(HEAVY_TAGS)));

        registerTier(project, "integrationTest", "integration",
                "Runs tests tagged 'integration' (needs Docker and the Compose stack).");
        registerTier(project, "e2eTest", "e2e", "Runs tests tagged 'e2e'.");
        registerTier(project, "drillTest", "drill", "Runs tests tagged 'drill'.");

        project.getTasks().withType(Test.class).configureEach(test -> {
            test.getTestLogging().events(TestLogEvent.PASSED, TestLogEvent.SKIPPED, TestLogEvent.FAILED);
            test.getTestLogging().setExceptionFormat(TestExceptionFormat.FULL);
            // Same JSSE setting the server's main() applies: no stateless TLS session tickets.
            test.systemProperty("jdk.tls.server.enableSessionTicketExtension", "false");
            if (MAY_BE_EMPTY.contains(test.getName())) {
                test.getFailOnNoDiscoveredTests().set(false);
            }
        });
    }

    private static void addTestDependencies(Project project) {
        VersionCatalog libs = project.getExtensions().getByType(VersionCatalogsExtension.class).named("libs");
        DependencyHandler deps = project.getDependencies();
        Provider<MinimalExternalModuleDependency> bootBom = lib(libs, "spring-boot-dependencies");
        deps.addProvider("testImplementation", bootBom.map(deps::platform));
        deps.addProvider("testImplementation", lib(libs, "junit-jupiter"));
        deps.addProvider("testImplementation", lib(libs, "assertj-core"));
        deps.addProvider("testRuntimeOnly", bootBom.map(deps::platform));
        deps.addProvider("testRuntimeOnly", lib(libs, "junit-platform-launcher"));
    }

    private static Provider<MinimalExternalModuleDependency> lib(VersionCatalog libs, String alias) {
        return libs.findLibrary(alias)
                .orElseThrow(() -> new IllegalStateException("libs.versions.toml is missing '" + alias + "'"));
    }

    private static void registerTier(Project project, String name, String tag, String description) {
        SourceSet testSourceSet = project.getExtensions().getByType(SourceSetContainer.class)
                .getByName(SourceSet.TEST_SOURCE_SET_NAME);
        project.getTasks().register(name, Test.class, task -> {
            task.setDescription(description);
            task.setGroup("verification");
            task.setTestClassesDirs(testSourceSet.getOutput().getClassesDirs());
            task.setClasspath(testSourceSet.getRuntimeClasspath());
            task.useJUnitPlatform(junit -> junit.includeTags(tag));
            task.shouldRunAfter(project.getTasks().named("test"));
        });
    }
}
