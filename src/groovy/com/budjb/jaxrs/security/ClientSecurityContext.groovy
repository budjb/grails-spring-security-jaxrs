/*
 * Copyright 2013 Bud Byrd
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

public class ClientSecurityContext {
    /**
     * Name assigned to anonymous clients.
     */
    private static final String ANONYMOUS_KEY = '__anonymous__'

    /**
     * An instance of an anonymous client.
     */
    public static final ClientSecurityContext ANONYMOUS = new ClientSecurityContext(ANONYMOUS_KEY)

    /**
     * API key associated with the client.
     */
    public String apiKey

    /**
     * Whether the
     */
    public boolean getIsAnonymous() {
        return apiKey == ANONYMOUS_KEY
    }

    /**
     * Constructor.
     *
     * @param apiKey
     */
    public ClientSecurityContext(String apiKey) {
        this.apiKey = apiKey
    }

    /**
     * Return the client instance for the api key.
     *
     * @return Client instance associated with the api key, or null if anonymous.
     */
    public JaxrsClient getClient() {
        if (getIsAnonymous()) {
            return null
        }

        return JaxrsClient.find { apiKey == this.apiKey }
    }
}
