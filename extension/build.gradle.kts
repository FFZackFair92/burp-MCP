plugins {
    java
}

repositories {
    mavenCentral()
}

dependencies {
    // Montoya API: fornita da Burp a runtime, quindi solo compileOnly.
    compileOnly("net.portswigger.burp.extensions:montoya-api:2026.4")
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(17))
    }
}

tasks.jar {
    archiveBaseName.set("burp-mcp-bridge")
    archiveVersion.set("0.1.0")
}
