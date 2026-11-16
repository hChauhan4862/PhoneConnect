plugins {
    id("com.android.application") version "8.9.1"
    id("org.jetbrains.kotlin.android") version "2.4.21"
    id("com.google.protobuf") version "0.10.1"
}

android {
    namespace = "com.phoneconnect.agent"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.phoneconnect.agent"
        minSdk = 28
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildFeatures {
        buildConfig = false
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    testOptions {
        unitTests.isIncludeAndroidResources = true
        unitTests.all {
            it.useJUnit()
            // Structural tests read the module's own sources, and Robolectric needs the
            // resource path to resolve against a predictable module directory.
            it.workingDir = projectDir
        }
    }

    lint {
        abortOnError = true
        checkReleaseBuilds = true
    }
}

kotlin {
    // JDK 21 comes from a Gradle toolchain, not a machine-specific path in gradle.properties.
    jvmToolchain(21)
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

protobuf {
    protoc {
        artifact = "com.google.protobuf:protoc:4.36.2"
    }
    generateProtoTasks {
        all().configureEach {
            builtins {
                // Messages are wire-compatible with prost; the lite runtime keeps the
                // agent free of the full protobuf reflection stack.
                create("java") {
                    option("lite")
                }
            }
        }
    }
}

dependencies {
    // The agent compiles the shared schema in ../../proto. It is declared as a proto input,
    // not copied into this module, so the generated types always match the Rust crates.
    protobuf(files("../../proto"))

    implementation("androidx.core:core-ktx:1.19.1")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")
    implementation("com.google.protobuf:protobuf-javalite:4.36.2")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.robolectric:robolectric:4.17")
    testImplementation("androidx.test:core:1.6.1")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.11.0")
    testImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")
}
