/*
 * Copyright 2014 Bud Byrd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.budjb.jaxrs.security.provider

import grails.util.Holders

import javax.servlet.http.HttpServletRequest
import org.apache.log4j.Logger
import org.codehaus.groovy.grails.commons.GrailsApplication

import com.budjb.jaxrs.security.AuthenticationProvider
import com.budjb.jaxrs.security.ClientSecurityContext
import com.budjb.jaxrs.security.JaxrsClient
import com.budjb.jaxrs.security.exception.ForbiddenClientException
import com.budjb.jaxrs.security.exception.UnauthorizedClientException

class QueryApiKeyAuthenticationProvider extends AuthenticationProvider {
    /**
     * Grails application
     */
    GrailsApplication grailsApplication

    /**
     * Logger.
     */
    protected static Logger log = Logger.getLogger(QueryApiKeyAuthenticationProvider)

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
        String apiKey = request.getParameter(getQueryParameter())

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

    /**
     * Returns the query parameter that contains the parameter name in the query string.
     *
     * @return
     */
    protected String getQueryParameter() {
        return grailsApplication.config.jaxrs.security.apiKey.query ?: 'apikey'
    }
}
