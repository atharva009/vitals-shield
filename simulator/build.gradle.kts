plugins {
    id("vitalsshield.java-conventions")
    application
}

dependencies {
    implementation(project(":crypto-common"))
    implementation(libs.nimbus.jose.jwt)
    implementation(libs.bcpkix)
}

application {
    mainClass = "com.vitalsshield.simulator.SimulatorMain"
}
