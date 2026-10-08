plugins { kotlin("multiplatform") version "2.4.0" }

// linuxX64 goes into the Docker image; macosArm64 is for trying the endpoint locally.
kotlin {
    listOf(linuxX64(), macosArm64()).forEach {
        it.binaries.executable {
            baseName = "endpoint"
            entryPoint = "neton.quic.interop.main"
        }
    }
    sourceSets {
        nativeMain.dependencies { implementation("com.netonstream:quic:0.1.0") }
    }
}
