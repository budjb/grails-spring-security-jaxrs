package com.budjb.jaxrs.security.provider

import grails.util.Holders

import javax.servlet.http.HttpServletRequest

import com.budjb.jaxrs.security.AuthenticationProvider
import com.budjb.jaxrs.security.ClientSecurityContext
import com.budjb.jaxrs.security.JaxrsClient
import com.budjb.jaxrs.security.exception.ForbiddenClientException
import com.budjb.jaxrs.security.exception.UnauthorizedClientException

class QueryApiKeyAuthenticationProvider extends AuthenticationProvider {
    /**
     * Returns the name of this provider.
     */
    public String getKey() {
        return 'query-apikey'
    }

    /**
     * Returns the name of the client "type" used to identify users along with their principal identity.
     *
     * @return
     */
    public String getClientType() {
        return "apikey"
    }

    /**
     * Attempts to authenticate a user.
     */
    public ClientSecurityContext authenticate(HttpServletRequest request) throws UnauthorizedClientException, ForbiddenClientException {
        // Grab the api key
        String apiKey = request.getParameter('apikey')

        // Done if the key is not present
        if (!apiKey) {
            return null
        }

        // If the client doesn't exist, skip
        if (!JaxrsClient.find { principal == apiKey && provider == getClientType() }) {
            throw new UnauthorizedClientException("Could not validate API key.")
        }

        // Create the credentials object
        ApiKeyCredentials credentials = new ApiKeyCredentials(apiKey)

        return new ClientSecurityContext(credentials)
    }
}
