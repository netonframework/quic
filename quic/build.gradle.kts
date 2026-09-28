plugins { kotlin("multiplatform") }

// Same targets as com.netonstream:io (resolved from mavenLocal until 0.2.0 is on Maven Central).
kotlin {
    linuxX64(); linuxArm64()
    macosArm64(); macosX64()
    mingwX64()
    iosArm64(); iosSimulatorArm64(); iosX64()
    androidNativeArm64(); androidNativeArm32(); androidNativeX64(); androidNativeX86()

    sourceSets {
        commonMain.dependencies { api("com.netonstream:io:0.2.0-SNAPSHOT") }
        commonTest.dependencies { implementation(kotlin("test")) }
    }
}
