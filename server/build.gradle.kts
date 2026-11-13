plugins {
    id("vitalsshield.java-conventions")
    alias(libs.plugins.spring.boot)
}

dependencies {
    implementation(platform(libs.spring.boot.dependencies))
    implementation(platform(libs.aws.sdk.bom))

    implementation(project(":crypto-common"))
    implementation(libs.spring.boot.starter.webflux)
    implementation(libs.spring.boot.starter.jdbc)
    implementation(libs.flyway.core)
    implementation(libs.flyway.database.postgresql)
    runtimeOnly(libs.postgresql)
    implementation(libs.aws.kms)
    implementation(libs.bcpkix)
    implementation(libs.nimbus.jose.jwt)

    testImplementation(platform(libs.spring.boot.dependencies))
    testImplementation(platform(libs.testcontainers.bom))
    testImplementation(libs.spring.boot.starter.test)
    testImplementation(libs.reactor.test)
    testImplementation(libs.testcontainers.postgresql)
    testImplementation(libs.testcontainers.junit.jupiter)
}
