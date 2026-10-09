plugins {
    kotlin("multiplatform") version "2.4.20" apply false
}

// Kotlin floor 2.4.20: anything below it (2.4.20 Beta / RC included) is refused. The stack and the Neton
// repositories share one Kotlin line; mixed versions break K/N klibs in ways that are hard to read.
run {
    val required = KotlinVersion(2, 4, 20)
    val actual = org.jetbrains.kotlin.gradle.plugin.getKotlinPluginVersion(logger)
    val parts = actual.substringBefore('-').split('.').map { it.toIntOrNull() ?: 0 } + listOf(0, 0, 0)
    val parsed = KotlinVersion(parts[0], parts[1], parts[2])
    require(parsed > required || (parsed == required && '-' !in actual)) {
        "Kotlin $actual is below the required minimum $required. Upgrade the Kotlin Gradle plugin."
    }
}
allprojects {
    group = "com.netonstream"
    version = "0.2.0"
}
apply(from = "gradle/publishing.gradle.kts")
