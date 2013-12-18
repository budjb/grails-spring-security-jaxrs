package com.budjb.jaxrs.security.provider

import com.budjb.jaxrs.security.ClientCredentials

class ApiKeyCredentials extends ClientCredentials {
    public ApiKeyCredentials(String apiKey) {
        principal = apiKey
        provider = 'apikey'
    }
}
