// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// Gradle manifest for the N-AALP Kotlin reference SDK (draft-bubblefish-naalp-00).
// The `-kotlin` artifact suffix disambiguates this from the sibling `naalp-java` artifact.
//
//   ./gradlew build            # compile + run the main()-driven KAT and smoke tests
//   ./gradlew publishToMavenLocal
//
// The crypto leg (deterministic ML-DSA / Ed25519) is Bouncy Castle bcprov-jdk18on:1.85.

plugins {
    kotlin("jvm") version "2.4.0"
    `maven-publish`
    signing
}

group = "sh.bubblefish"
version = "0.1.0"

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.bouncycastle:bcprov-jdk18on:1.85")
    testImplementation(kotlin("stdlib"))
}

kotlin {
    jvmToolchain(21)
}

// The main()-driven tests live under src/test/kotlin; they are compiled into the test source set
// and exercised through the two verification tasks below (no JUnit runner is used).
tasks.register<JavaExec>("workedExampleKat") {
    group = "verification"
    description = "Reproduce the byte-level worked object and verify/tamper-check it."
    dependsOn("testClasses")
    classpath = sourceSets["test"].runtimeClasspath
    mainClass.set("sh.bubblefish.naalp.WorkedExampleKatKt")
}

tasks.register<JavaExec>("primitivesSmoke") {
    group = "verification"
    description = "Run the standards-anchored primitives smoke suite."
    dependsOn("testClasses")
    classpath = sourceSets["test"].runtimeClasspath
    mainClass.set("sh.bubblefish.naalp.PrimitivesSmokeKt")
}

tasks.named("check") {
    dependsOn("workedExampleKat", "primitivesSmoke")
}

// Maven Central REQUIRES a -sources.jar AND a -javadoc.jar for every published module; attach both.
// (For a kotlin("jvm") project the javadoc jar is empty by default — apply the Dokka plugin for
// rich Kotlin API docs; an empty javadoc jar still satisfies Central's mandatory-artifact rule.)
java {
    withSourcesJar()
    withJavadocJar()
}

publishing {
    // Maven Central deploy target via the Central Portal's OSSRH Staging API (Sonatype provides no
    // official Gradle plugin — see central.sonatype.org/publish/publish-portal-gradle; for a
    // one-command Central release the operator may instead adopt a community plugin such as
    // com.vanniktech.maven.publish, GradleUp/nmcp, or JReleaser). Credentials come from CI secrets;
    // with none set, only `publishToMavenLocal` is usable, so the dry-run `gradle build` never needs them.
    repositories {
        maven {
            name = "central"
            url = uri("https://ossrh-staging-api.central.sonatype.com/service/local/staging/deploy/maven2/")
            credentials {
                username = System.getenv("MAVEN_CENTRAL_USERNAME")
                password = System.getenv("MAVEN_CENTRAL_PASSWORD")
            }
        }
    }
    publications {
        create<MavenPublication>("maven") {
            from(components["java"])
            artifactId = "naalp-kotlin"
            pom {
                name.set("N-AALP Kotlin SDK")
                description.set(
                    "Reference SDK for N-AALP (Native Agentic Application Layer Protocol), " +
                        "draft-bubblefish-naalp-00 — the Kotlin implementation."
                )
                url.set("https://github.com/bubblefish-tech/naalp_protocol")
                licenses {
                    license {
                        name.set("Apache-2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0")
                    }
                }
                developers {
                    developer {
                        name.set("Shawn Sammartano")
                        email.set("naalp-editor@bubblefish.sh")
                    }
                }
                scm {
                    url.set("https://github.com/bubblefish-tech/naalp_protocol")
                    connection.set("scm:git:https://github.com/bubblefish-tech/naalp_protocol.git")
                }
            }
        }
    }
}

// GPG-sign every published artifact (Central requires a detached .asc signature per file). The key
// and passphrase come from CI secrets (MAVEN_GPG_PRIVATE_KEY / MAVEN_GPG_PASSPHRASE); the block is
// guarded so the dry-run `gradle build` (no key present) does not attempt to sign.
signing {
    val signingKey = System.getenv("MAVEN_GPG_PRIVATE_KEY")
    val signingPass = System.getenv("MAVEN_GPG_PASSPHRASE")
    if (!signingKey.isNullOrBlank()) {
        useInMemoryPgpKeys(signingKey, signingPass)
        sign(publishing.publications["maven"])
    }
}
