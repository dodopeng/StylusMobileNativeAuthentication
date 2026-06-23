plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

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
}

dependencies {
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
    // Biometric prompt + CryptoObject binding for hardware-gated signing.
    implementation("androidx.biometric:biometric:1.1.0")
    // org.json ships with the Android platform — no extra JSON dependency.

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.8.1")
}
