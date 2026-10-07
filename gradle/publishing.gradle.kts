import org.gradle.api.publish.PublishingExtension
import org.gradle.api.publish.maven.MavenPublication
import org.gradle.plugins.signing.SigningExtension

subprojects {
    apply(plugin = "maven-publish")
    apply(plugin = "signing")
    afterEvaluate {
        val publications = extensions.getByType<PublishingExtension>()
        val docs = tasks.register<Jar>("apiDocsJar") {
            archiveClassifier.set("javadoc")
            from(rootProject.file("README.md"))
        }
        publications.publications.withType<MavenPublication>().configureEach {
            artifact(docs)
            pom {
                name.set("Neton Stream " + project.name)
                description.set("Kotlin/Native " + project.name + " protocol library on com.netonstream:io")
                url.set("https://github.com/netonframework/" + rootProject.name.removeSuffix("-build"))
                licenses { license { name.set("Apache-2.0"); url.set("https://www.apache.org/licenses/LICENSE-2.0") } }
                developers {
                    developer {
                        id.set("zoujiaqing")
                        name.set("zoujiaqing")
                        email.set("zoujiaqing@gmail.com")
                        organization.set("Neton Stream")
                        organizationUrl.set("https://netonstream.com")
                    }
                }
                scm {
                    url.set("https://github.com/netonframework/" + rootProject.name.removeSuffix("-build"))
                    connection.set("scm:git:https://github.com/netonframework/" + rootProject.name.removeSuffix("-build") + ".git")
                }
            }
        }
        publications.repositories {
            maven { name = "stagingLocal"; url = rootProject.layout.buildDirectory.dir("staging-repo").get().asFile.toURI() }
        }
        extensions.configure<SigningExtension> {
            val key = findProperty("signingInMemoryKey") as String?
            if (!key.isNullOrBlank()) {
                useInMemoryPgpKeys(key, findProperty("signingInMemoryKeyPassword") as String? ?: "")
                sign(publications.publications)
            }
        }
        tasks.withType<org.gradle.api.publish.maven.tasks.AbstractPublishToMaven>().configureEach {
            dependsOn(tasks.withType<org.gradle.plugins.signing.Sign>())
        }
    }
}
