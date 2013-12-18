package com.budjb.jaxrs.security

abstract class ClientCredentials {
    /**
     * User login.
     */
    String principal

    /**
     * Provider used to authenticate the user.
     */
    String provider
}
