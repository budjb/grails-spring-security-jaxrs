# Grails 3 upgrade for this plugin

Currently is working but has known issues.

# Known issues

1. Not all unit tests complete (due to new config objects in Grails 3) - help?

2. In order to use this plugin you require the grails jaxrs plugin, which is not currently on the public repositories for Grails 3. In build.gradle this project currently references a local jaxrs project, you will need to use this project which is available here: https://github.com/donald-jackson/grails-jaxrs

Spring Security Jaxrs integration plugin for Grails
---------------------------------------------------
See the documentation at http://budjb.github.io/grails-spring-security-jaxrs/doc/manual/index.html.
