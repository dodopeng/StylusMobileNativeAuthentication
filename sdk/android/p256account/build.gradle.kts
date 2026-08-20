plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    // M2 KPI is "published and publicly available". Without this the only
    // integration path is vendoring source.
    `maven-publish`
}

group = "xyz.heavenlydev"
version = "0.1.0"

android {
    namespace = "xyz.heavenlydev.p256account"
    compileSdk = 34

    defaultConfig {
        minSdk = 29 // StrongBox + BiometricPrompt(CryptoObject) reliably available from API 29
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }

    // Ship sources + javadoc so integrators get parameter names and KDoc in the
    // IDE rather than decompiled bytecode.
    publishing {
        singleVariant("release") {
            withSourcesJar()
            withJavadocJar()
        }
    }
}

publishing {
    publications {
        register<MavenPublication>("release") {
            afterEvaluate { from(components["release"]) }
            artifactId = "p256account"
            pom {
                name.set("P256Account Android SDK")
                description.set(
                    "Mobile-native smart account SDK for Arbitrum Stylus: hardware-backed " +
                        "P-256 (secp256r1) signing via StrongBox/TEE, EIP-712 authorisation, " +
                        "and pre-built DeFi action templates.",
                )
                url.set("https://github.com/dodopeng/StylusMobileNativeAuthentication")
                licenses {
                    license {
                        name.set("MIT License")
                        url.set("https://opensource.org/licenses/MIT")
                    }
                }
                developers {
                    developer {
                        id.set("dodopeng")
                        name.set("dodopeng")
                    }
                }
                scm {
                    url.set("https://github.com/dodopeng/StylusMobileNativeAuthentication")
                    connection.set("scm:git:https://github.com/dodopeng/StylusMobileNativeAuthentication.git")
                }
            }
        }
    }
    repositories {
        // `./gradlew :p256account:publishReleasePublicationToLocalRepository`
        // produces a consumable Maven layout under build/repo for smoke-testing
        // before any credentials are involved.
        maven {
            name = "local"
            url = uri(layout.buildDirectory.dir("repo"))
        }
        // Real publishing target. Credentials come from the environment so
        // nothing secret lands in the repo.
        maven {
            name = "gitHubPackages"
            url = uri("https://maven.pkg.github.com/dodopeng/StylusMobileNativeAuthentication")
            credentials {
                username = System.getenv("GITHUB_ACTOR") ?: ""
                password = System.getenv("GITHUB_TOKEN") ?: ""
            }
        }
    }
}

dependencies {
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
    // Biometric prompt + CryptoObject binding for hardware-gated signing.
    implementation("androidx.biometric:biometric:1.1.0")
    // org.json ships with the Android platform — no extra JSON dependency.

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.8.1")
    // On-device `org.json` is a stub in JVM unit tests; the real implementation
    // lets ActionsInteropTest read sdk/actions.golden.json directly rather than
    // duplicating the golden vectors into Kotlin source.
    testImplementation("org.json:json:20240303")
}
