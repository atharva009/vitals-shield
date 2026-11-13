plugins {
    // Auto-provisions the Java 21 toolchain when no local JDK 21 is installed.
    id("org.gradle.toolchains.foojay-resolver-convention") version "0.10.0"
}

rootProject.name = "vitalsshield"

include("crypto-common", "server", "simulator")
