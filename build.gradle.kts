plugins {
    kotlin("multiplatform") version "2.4.0" apply false
}
allprojects {
    group = "com.netonstream"
    version = "0.2.0"
}
apply(from = "gradle/publishing.gradle.kts")
