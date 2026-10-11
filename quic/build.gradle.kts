plugins { kotlin("multiplatform"); `maven-publish` }

// The targets com.netonstream:io and com.netonstream:openssl both provide (openssl has no 32-bit Android).
kotlin {
    // The JVM (desktop and Android apps): UDP through neton-io's NIO reactor, TLS through openssl-kotlin's JNI library.
    // Bytecode 1.8, API 2.2 and stdlib 2.2.21 so Android hosts on Kotlin 2.1 can use it (as neton-io and openssl).
    coreLibrariesVersion = "2.2.21"
    // Language 2.2 for every source set the JVM compiles (KMP also requires a source set to be no older than the ones it
    // depends on, so native-only ones may stay newer): class metadata then says 2.2, which a Kotlin 2.1 compiler still
    // reads (one version ahead); with the 2.4 default it refuses to compile against these classes.
    jvm {
        compilerOptions {
            jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_1_8)
            apiVersion.set(org.jetbrains.kotlin.gradle.dsl.KotlinVersion.KOTLIN_2_2)
            languageVersion.set(org.jetbrains.kotlin.gradle.dsl.KotlinVersion.KOTLIN_2_2)
        }
        compilations.configureEach { allKotlinSourceSets.forAll { it.languageSettings.languageVersion = "2.2" } }
    }
    linuxX64(); linuxArm64()
    macosArm64(); macosX64()
    mingwX64()
    iosArm64(); iosSimulatorArm64(); iosX64()
    androidNativeArm64(); androidNativeX64()

    sourceSets {
        commonMain.dependencies {
            api("com.netonstream:io:0.3.2")
            // TLS through the QUIC TLS facade; packet protection, key derivation and token / reset keys.
            api("com.netonstream:openssl:4.0.2-3")
        }
        commonTest.dependencies { implementation(kotlin("test")) }
        // neton-io's IoStream conformance suite (SPEC §3: streams as IoStream, neton-io SPEC §28.6).
        nativeTest.dependencies {
            implementation("com.netonstream:io-testkit:0.3.2")
            implementation(project(":quic-testkit"))
        }
    }
}
