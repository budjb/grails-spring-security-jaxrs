package org.grails.plugins.springsecurity.jaxrs.test

import org.springframework.security.access.annotation.Secured

import javax.ws.rs.*

@Path('/api/shared')
class SharedResource {
    @GET
    @Secured(['ROLE_READONLY'])
    String sharedGet() {
        return "ok"
    }

    @POST
    @Secured(['ROLE_USER'])
    String sharedPost() {
        return "This is a POST API."
    }

    @PUT
    @Secured(['IS_AUTHENTICATED_ANONYMOUSLY'])
    String sharedPut() {
        return "ok"
    }

    @DELETE
    String sharedDelete() {
        return "ok"
    }
}
