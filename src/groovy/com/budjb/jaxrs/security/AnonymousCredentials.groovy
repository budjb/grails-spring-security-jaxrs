package com.budjb.jaxrs.security

class AnonymousCredentials extends ClientCredentials {
    public AnonymousCredentials() {
        principal = 'anonymous'
    }
}
