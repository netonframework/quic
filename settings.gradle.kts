pluginManagement {
    repositories { gradlePluginPortal(); mavenCentral() }
}
dependencyResolutionManagement {
    repositories {
        // -PreleaseRepositories=<dir>,<dir>…: unreleased dependencies from local Maven repositories (a release
        // candidate's, in CI), ahead of Maven Central.
        providers.gradleProperty("releaseRepositories").orNull?.split(",")?.forEach { path ->
            maven { url = uri(path) }
        }
        mavenCentral()
    }
}
rootProject.name = "quic-build"
include(":quic")
// com.netonstream:quic-testkit: the TLS test double (MockTls), for tests of quic and of protocols on it (http3). Never
// for production: it does no real TLS.
include(":quic-testkit")
