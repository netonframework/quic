plugins { kotlin("multiplatform"); `maven-publish` }

// The targets com.netonstream:io and com.netonstream:openssl both provide (openssl has no 32-bit Android).
kotlin {
    linuxX64(); linuxArm64()
    macosArm64(); macosX64()
    mingwX64()
    iosArm64(); iosSimulatorArm64(); iosX64()
    androidNativeArm64(); androidNativeX64()

    sourceSets {
        commonMain.dependencies { api("com.netonstream:io:0.3.0") }
        // Packet protection, key derivation and token / reset keys.
        nativeMain.dependencies { api("com.netonstream:openssl:4.0.2") }
        commonTest.dependencies { implementation(kotlin("test")) }
        // neton-io's IoStream conformance suite (SPEC §3: streams as IoStream, neton-io SPEC §28.6).
        nativeTest.dependencies {
            implementation("com.netonstream:io-testkit:0.3.0")
            implementation(project(":quic-testkit"))
        }
    }
}
