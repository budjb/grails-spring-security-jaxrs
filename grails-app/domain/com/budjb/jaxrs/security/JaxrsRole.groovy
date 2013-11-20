package com.budjb.jaxrs.security

class JaxrsRole {
    /**
     * Name of the role.
     */
    String name

    /**
     * Field constraints.
     */
    static constraints = {
        name blankable: false
    }
}
