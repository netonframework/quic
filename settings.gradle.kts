pluginManagement {
    repositories { gradlePluginPortal(); mavenCentral() }
}
dependencyResolutionManagement {
    repositories { mavenLocal(); mavenCentral() }
}
rootProject.name = "quic-build"
include(":quic")
