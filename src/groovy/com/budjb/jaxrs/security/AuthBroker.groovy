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
        // Whether we're allowing any authentication provider
        boolean allowAll = providerKeys.size() == 1 && providerKeys[0] == '*'

        // Check each provider
        for (Map.Entry<String, AuthenticationProvider> providerEntry : providers) {
            // Lower case the provider key
            String providerKey = providerEntry.key.toLowerCase()

            // If the key is not valid, skip it
            if (!allowAll && !providerKeys.contains(providerKey)) {
                continue
            }

            // Attempt authentication
            ClientSecurityContext context = providerEntry.value.authenticate(request)

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
