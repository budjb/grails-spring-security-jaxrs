package org.grails.plugins.springsecurity.jaxrs.test

import org.springframework.security.access.annotation.Secured

import javax.ws.rs.GET
import javax.ws.rs.Path

@Path('/api/class_security')
@Secured(['ROLE_READONLY'])
class ClassSecurityResource {
    @GET
    String index() {
        return "ok"
    }

    @GET
    @Path('/anonymous')
    @Secured(['IS_AUTHENTICATED_ANONYMOUSLY'])
    String anonymous() {
        return "ok"
    }

    @GET
    @Path('/override')
    @Secured(['ROLE_USER'])
    String override() {
        return "ok"
    }
}
