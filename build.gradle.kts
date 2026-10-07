plugins {
    kotlin("multiplatform") version "2.4.0" apply false
}
allprojects {
    group = "com.netonstream"
    version = "0.1.0"
}
apply(from = "gradle/publishing.gradle.kts")
