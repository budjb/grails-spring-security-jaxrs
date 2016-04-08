package org.grails.springsecurity.jaxrs.test

import grails.boot.GrailsApp
import grails.boot.config.GrailsAutoConfiguration
import grails.plugin.springsecurity.SecurityFilterPosition
import grails.plugin.springsecurity.SpringSecurityUtils

class Application extends GrailsAutoConfiguration {
    static void main(String[] args) {
        GrailsApp.run(Application, args)
    }

    @Override
    void doWithApplicationContext() {
        SpringSecurityUtils.clientRegisterFilter('requestRoleFilter', SecurityFilterPosition.SECURITY_CONTEXT_FILTER.order + 15)
    }
}