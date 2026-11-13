plugins {
    id("vitalsshield.java-conventions")
    `java-library`
}

dependencies {
    api(libs.bcpkix)
    api(libs.nimbus.jose.jwt)
}
