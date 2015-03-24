package com.budjb.jaxrs.security

import grails.plugin.springsecurity.annotation.Secured

class IndexController {
    @Secured(['ROLE_USER'])
    def index() {
        render "hi"
    }

    @Secured(['IS_AUTHENTICATED_ANONYMOUSLY'])
    def anonymous() {
        render "Hello, guest."
    }

    def norule() {
        render "Welcome to no man's land."
    }
}
