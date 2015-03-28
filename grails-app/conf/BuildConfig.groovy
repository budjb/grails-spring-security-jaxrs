grails.project.class.dir = "target"

grails.project.dependency.resolver = "maven"

grails.project.dependency.resolution = {
    inherits "global"
    log "warn"

    repositories {
        grailsCentral()
        mavenLocal()
        mavenCentral()
        mavenRepo "http://maven.restlet.com"
    }

    dependencies {
        runtime('net.sf.ehcache:ehcache:2.9.1') {
            export = false
        }
    }

    plugins {
        build(":release:3.0.1", ":rest-client-builder:2.0.3") {
            export = false
        }

        compile ':spring-security-core:2.0-RC4'
        compile ':jaxrs:0.11'
    }
}
