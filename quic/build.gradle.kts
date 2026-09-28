plugins { kotlin("multiplatform") }

// The targets com.netonstream:io and com.netonstream:openssl both provide (openssl has no 32-bit Android).
kotlin {
    linuxX64(); linuxArm64()
    macosArm64(); macosX64()
    mingwX64()
    iosArm64(); iosSimulatorArm64(); iosX64()
    androidNativeArm64(); androidNativeX64()

    sourceSets {
        commonMain.dependencies { api("com.netonstream:io:0.2.0-SNAPSHOT") }
        // Packet protection, key derivation and token / reset keys (resolved from mavenLocal).
        nativeMain.dependencies { api("com.netonstream:openssl:4.0.2") }
        commonTest.dependencies { implementation(kotlin("test")) }
    }
}
