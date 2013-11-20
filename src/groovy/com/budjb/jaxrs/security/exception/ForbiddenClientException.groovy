package com.budjb.jaxrs.security.exception

class ForbiddenClientException extends Exception {
    public ForbiddenClientException() {
        super()
    }

    public ForbiddenClientException(String message) {
        super(message)
    }

    public ForbiddenClientException(String message, Throwable cause) {
        super(message, cause)
    }
}
