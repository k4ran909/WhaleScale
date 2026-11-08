plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

// The release version, e.g. -PwsVersion=0.1.9 (build-go.sh stamps the same
// one into the Go core). versionCode must grow with every release:
// 0.1.9 -> 109, 1.2.3 -> 10203.
val wsVersion = (findProperty("wsVersion") as String?)?.removePrefix("v") ?: "0.1.8"
val wsVersionCode = wsVersion.substringBefore("-").split(".").map { it.toIntOrNull() ?: 0 }
    .let { (it.getOrElse(0) { 0 } * 10000) + (it.getOrElse(1) { 0 } * 100) + it.getOrElse(2) { 0 } }
    .coerceAtLeast(1)

// Release signing, from the environment so no key lives in the repository
// (see docs/guides/android.md). Without it the release APK is unsigned.
val keystore = System.getenv("WS_ANDROID_KEYSTORE")

android {
    namespace = "io.github.k4ran909.whalescale"
    compileSdk = 35
    buildToolsVersion = "35.0.0"

    defaultConfig {
        applicationId = "io.github.k4ran909.whalescale"
        minSdk = 26
        targetSdk = 35
        versionCode = wsVersionCode
        versionName = wsVersion
        // The CPUs build-go.sh builds the Go core for; other libraries'
        // extra ones (32-bit x86) would install where the core can't run.
        ndk { abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64") }
    }
    // Same as build-go.sh and scripts/ci/android-sdk.sh.
    ndkVersion = "27.2.12479018"

    packaging {
        // The Go core is ~28 MB per CPU; compressed in the APK it is about a
        // third of that (Android unpacks it when installing).
        jniLibs.useLegacyPackaging = true
    }

    signingConfigs {
        if (keystore != null) {
            create("release") {
                storeFile = file(keystore)
                storePassword = System.getenv("WS_ANDROID_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("WS_ANDROID_KEY_ALIAS") ?: "whalescale"
                keyPassword = System.getenv("WS_ANDROID_KEY_PASSWORD") ?: System.getenv("WS_ANDROID_KEYSTORE_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            // The Go core is called through JNI by name: shrinking would
            // need keep rules for it, and saves little next to the Go library.
            isMinifyEnabled = false
            if (keystore != null) signingConfig = signingConfigs.getByName("release")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
}

dependencies {
    // The Go core: ../build-go.sh makes it with gomobile bind.
    implementation(files("libs/whalescale.aar"))

    implementation(platform("androidx.compose:compose-bom:2024.12.01"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    // QR scanning without Google Play services.
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
    debugImplementation("androidx.compose.ui:ui-tooling")
}
