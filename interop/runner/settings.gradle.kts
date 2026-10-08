pluginManagement {
    repositories { gradlePluginPortal(); mavenCentral() }
}
dependencyResolutionManagement {
    repositories { mavenCentral() }
}
// The quic-interop-runner endpoint (README.md here). A build of its own so that the repository's publishing never sees
// it; com.netonstream:quic comes from the checkout two levels up.
rootProject.name = "quic-interop-endpoint"
includeBuild("../..")
