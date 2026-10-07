plugins { kotlin("multiplatform"); `maven-publish` }

// com.netonstream:quic-testkit: the deterministic TLS test double (MockTls) for tests of quic and of protocols built on
// it (http3), where a handshake without certificates or key exchange keeps tests deterministic. Test-only: it does no
// real TLS and production code must not depend on it. Same targets as quic.
kotlin {
    linuxX64(); linuxArm64()
    macosArm64(); macosX64()
    mingwX64()
    iosArm64(); iosSimulatorArm64(); iosX64()
    androidNativeArm64(); androidNativeX64()

    sourceSets {
        commonMain.dependencies { api(project(":quic")) }
    }
}
