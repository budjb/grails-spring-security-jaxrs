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
     * An instance of an anonymous client.
     */
    public static final ClientSecurityContext ANONYMOUS = new ClientSecurityContext(new AnonymousCredentials())

    /**
     * Credentials used to authenticate the user.
     */
    private ClientCredentials credentials

    /**
     * Constructor.
     *
     * @param apiKey
     */
    public ClientSecurityContext(ClientCredentials credentials) {
        this.credentials = credentials
    }

    /**
     * Whether the security context is anonymous.
     */
    public boolean getIsAnonymous() {
        return (credentials instanceof AnonymousCredentials)
    }

    /**
     * Returns the logged in user.
     *
     * @return
     */
    public JaxrsClient getClient() {
        if (!credentials || getIsAnonymous()) {
            return null
        }

        return JaxrsClient.find { principal == credentials.principal && provider == credentials.provider }
    }
}
