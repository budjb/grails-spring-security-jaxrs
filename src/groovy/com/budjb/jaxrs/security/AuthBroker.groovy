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
package com.budjb.jaxrs.security

import javax.servlet.http.HttpServletRequest
import org.apache.log4j.Logger

class AuthBroker {
    /**
     * List of registered authentication providers.
     */
    private Map<String, AuthenticationProvider> providers = [:]

    /**
     * Logger.
     */
    private Logger log = Logger.getLogger(getClass())

    /**
     * Attempts to log in a user.
     *
     * @param request
     * @param providers
     * @return
     */
    public ClientSecurityContext authenticate(HttpServletRequest request, List<String> providerKeys) {
        // Check each key
        for (String providerKey : providerKeys ?: []) {
            // Lower case the key
            providerKey = providerKey.toLowerCase()

            // If the key is not valid, skip it
            if (!providers.containsKey(providerKey)) {
                log.warn("provider \"${providerKey}\" is invalid")
                continue
            }

            // Attempt authentication
            ClientSecurityContext context = providers[providerKey].authenticate(request)

            // If we have a successful login, return it
            if (context) {
                return context
            }
        }

        return null
    }

    /**
     * Registers an authentication provider.
     *
     * @param provider
     */
    public void registerAuthenticationProvider(AuthenticationProvider provider) {
        providers[provider.key.toLowerCase()] = provider
    }
}
