package com.budjb.jaxrs.security.exception

class UnauthorizedClientException extends Exception {
    public UnauthorizedClientException() {
        super()
    }

    public UnauthorizedClientException(String message) {
        super(message)
    }

    public UnauthorizedClientException(String message, Throwable cause) {
        super(message, cause)
    }
}
