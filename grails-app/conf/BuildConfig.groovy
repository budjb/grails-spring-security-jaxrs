grails.project.class.dir = "target"

grails.project.dependency.resolver = "maven"

grails.project.dependency.resolution = {
    inherits("global")

    log "warn"

    repositories {
        grailsCentral()
        mavenLocal()
        mavenCentral()
        mavenRepo "http://maven.restlet.com"
    }

    dependencies {
        runtime 'net.sf.ehcache:ehcache:2.9.1'
    }

    plugins {
        build(":release:3.0.1",
              ":rest-client-builder:1.0.3",
              ":tomcat:7.0.55") {
            export = false
        }

        compile ':spring-security-core:2.0-RC4'
        compile ':jaxrs:0.11'
    }
}
