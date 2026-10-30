import java.util.Properties
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

// Local values from secrets.properties (git-ignored); see secrets.properties.example.
val secrets = Properties().apply {
    rootProject.file("secrets.properties").takeIf { it.exists() }?.inputStream()?.use(::load)
}
fun secret(name: String, default: String = "") = secrets.getProperty(name, default)

android {
    namespace = "com.woosmap.app.woozies"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.woosmap.app.woozies"
        minSdk = 28
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"
        buildConfigField("String", "WOOSMAP_API_KEY", "\"${secret("WOOSMAP_API_KEY")}\"")
        buildConfigField("String", "PROXY_BASE_URL", "\"${secret("PROXY_BASE_URL", "http://10.0.2.2:8000")}\"")
        buildConfigField("long", "PLAY_INTEGRITY_PROJECT_NUMBER", "${secret("PLAY_INTEGRITY_PROJECT_NUMBER", "0")}L")
        // Must be listed in ATTEST_DEBUG_TOKENS on the proxy. Release builds never send one.
        buildConfigField("String", "DEBUG_ATTESTATION_TOKEN", "\"\"")
    }

    buildTypes {
        debug {
            buildConfigField("String", "DEBUG_ATTESTATION_TOKEN", "\"woozies-simulator-debug\"")
        }
        release {
            isMinifyEnabled = false
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    compilerOptions { jvmTarget.set(JvmTarget.JVM_17) }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2025.01.00")
    implementation(composeBom)
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    implementation("com.google.android.play:integrity:1.4.0")

    testImplementation("junit:junit:4.13.2")
    // Real org.json for JVM unit tests (Android's copy is a stub there)
    testImplementation("org.json:json:20240303")
}
