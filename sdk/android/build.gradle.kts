// Root build file. Plugin versions are declared here and applied (apply false)
// so the library module can opt in without re-declaring versions.
plugins {
    id("com.android.library") version "8.5.2" apply false
    id("com.android.application") version "8.5.2" apply false
    id("org.jetbrains.kotlin.android") version "1.9.24" apply false
}
