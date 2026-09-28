pluginManagement {
    repositories { gradlePluginPortal(); mavenCentral() }
}
dependencyResolutionManagement {
    repositories { mavenLocal(); mavenCentral() }
}
rootProject.name = "quic-build"
include(":quic")
// com.netonstream:quic-testkit: the TLS test double (MockTls), for tests of quic and of protocols on it (http3). Never
// for production: it does no real TLS.
include(":quic-testkit")
