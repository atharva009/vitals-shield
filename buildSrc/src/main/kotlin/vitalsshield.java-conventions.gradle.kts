// Shared Java 21 toolchain, test dependencies, and the four test tiers.
plugins {
    java
}

val libs = extensions.getByType<VersionCatalogsExtension>().named("libs")
fun lib(alias: String) = libs.findLibrary(alias).get()

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(platform(lib("junit-bom")))
    testImplementation(lib("junit-jupiter"))
    testImplementation(lib("assertj-core"))
    testRuntimeOnly(lib("junit-platform-launcher"))
}

val heavyTags = arrayOf("integration", "e2e", "drill")

tasks.named<Test>("test") {
    useJUnitPlatform {
        excludeTags(*heavyTags)
    }
}

fun registerTier(name: String, tag: String, desc: String) =
    tasks.register<Test>(name) {
        description = desc
        group = "verification"
        testClassesDirs = sourceSets["test"].output.classesDirs
        classpath = sourceSets["test"].runtimeClasspath
        useJUnitPlatform {
            includeTags(tag)
        }
        // Tiers may legitimately discover zero tests (e2e/drill in Phase 0, or a
        // module with no integration tests). Gradle 8.14 passes on zero tests by
        // default; `failOnNoDiscoveredTests` only exists from Gradle 9 and must be
        // set to false here if the wrapper is ever upgraded.
        shouldRunAfter(tasks.named("test"))
    }

registerTier("integrationTest", "integration", "Runs tests tagged 'integration' (needs Docker + Compose stack).")
registerTier("e2eTest", "e2e", "Runs tests tagged 'e2e'.")
registerTier("drillTest", "drill", "Runs tests tagged 'drill'.")

tasks.withType<Test>().configureEach {
    testLogging {
        events("passed", "skipped", "failed")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}
