package com.budjb.jaxrs

import org.springframework.security.access.annotation.Secured

import javax.ws.rs.GET
import javax.ws.rs.Path

@Path('/api')
class IndexResource {
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
}
