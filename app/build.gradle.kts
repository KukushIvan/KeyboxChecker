import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
}

val localProperties = Properties()
val localPropertiesFile = rootProject.file("keystore.properties")
if (localPropertiesFile.exists()) {
    localProperties.load(localPropertiesFile.inputStream())
}

android {
    namespace = "io.github.kukushivan.keyboxchecker"
    compileSdk = 36

    defaultConfig {
        applicationId = "io.github.kukushivan.keyboxchecker"
        minSdk = 24
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"
    }

    signingConfigs {
        create("release") {
            val keystorePath = System.getenv("KEYSTORE_PATH") ?: localProperties.getProperty("keystore.path")
            val keystorePass = System.getenv("KEYSTORE_PASSWORD") ?: localProperties.getProperty("keystore.password")
            val keyAliasName = System.getenv("KEY_ALIAS") ?: localProperties.getProperty("keystore.alias")
            val keyAliasPass = System.getenv("KEY_PASSWORD") ?: localProperties.getProperty("keystore.alias_password")

            if (keystorePath != null && keystorePass != null && keyAliasName != null && keyAliasPass != null) {
                storeFile = file("${rootProject.projectDir}/$keystorePath")
                storePassword = keystorePass
                keyAlias = keyAliasName
                keyPassword = keyAliasPass
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = signingConfigs.getByName("release")
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
    }
    lint {
        baseline = file("lint-baseline.xml")
        disable += "PropertyEscape"
    }
    splits {
        abi {
            isEnable = true
            reset()
            include("arm64-v8a", "armeabi-v7a")
            isUniversalApk = false
        }
    }
}

dependencies {
    implementation("androidx.work:work-runtime-ktx:2.10.0")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.material3)
}