package com.budjb.jaxrs.security

class JaxrsClient {
    /**
     * Api Key
     */
    String apiKey

    /**
     * Client name
     */
    String name

    /**
     * Whether the key is active
     */
    boolean active = true

    /**
     * Date the key was created
     */
    Date dateCreated

    /**
     * Field constraints.
     */
    static constraints = {
        name blankable: false
        apiKey blankable: false
        dateCreated nullable: true
    }
}
