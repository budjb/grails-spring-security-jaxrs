package com.budjb.jaxrs.security

public enum AuthType {
    HEADER('header'),
    QUERY('query')

    String value

    public AuthType(String value) {
        this.value = value
    }
}
