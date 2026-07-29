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

java {
    withSourcesJar()
}

publishing {
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
