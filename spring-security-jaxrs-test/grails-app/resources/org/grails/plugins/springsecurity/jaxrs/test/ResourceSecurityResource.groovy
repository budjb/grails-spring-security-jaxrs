package org.grails.plugins.springsecurity.jaxrs.test

import org.springframework.security.access.annotation.Secured

import javax.ws.rs.GET
import javax.ws.rs.Path

@Path('/api/resource_security')
class ResourceSecurityResource {
    @GET
    @Secured(['ROLE_USER'])
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
    @Path('/norule')
    String norule() {
        return "ok"
    }
}
