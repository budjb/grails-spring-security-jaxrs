package org.grails.plugins.spring.security.jaxrs.support

import org.springframework.security.access.annotation.Secured

import javax.ws.rs.GET
import javax.ws.rs.POST
import javax.ws.rs.Path

@Path('/api/class_security')
@Secured(['ROLE_READONLY'])
class ClassSecurityResource {
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
    @Path('/inherit')
    String inherit() {
        return "Welcome to no man's land."
    }

    @POST
    @Path('/post')
    @Secured(['ROLE_USER'])
    String secured() {
        return "This is a POST API."
    }
}
