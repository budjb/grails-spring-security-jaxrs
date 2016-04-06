package org.grails.plugins.jaxrs.spring.security

import org.springframework.security.access.annotation.Secured

import javax.ws.rs.GET
import javax.ws.rs.POST
import javax.ws.rs.Path

@Path('/api/resource_security')
class ResourceSecurityResource {
    @GET
    @Secured(['ROLE_USER'])
    String index() {
        return "Hello, world!"
    }

    @GET
    @Path('/anonymous')
    @Secured(['IS_AUTHENTICATED_ANONYMOUSLY'])
    String anonymous() {
        return "Hello, guest."
    }

    @GET
    @Path('/norule')
    String norule() {
        return "Welcome to no man's land."
    }

    @POST
    @Path('/post')
    @Secured(['ROLE_USER'])
    String secured() {
        return "This is a POST API."
    }
}
