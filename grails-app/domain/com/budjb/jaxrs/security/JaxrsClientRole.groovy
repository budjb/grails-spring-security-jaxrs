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

class JaxrsClientRole implements Serializable {
    /**
     * Client
     */
    JaxrsClient client

    /**
     * Role
     */
    JaxrsRole role

    /**
     * Retrieve an instance of this domain based on a client and role.
     *
     * @param clientId
     * @param roleId
     * @return
     */
    static JaxrsClientRole get(long clientId, long roleId) {
        JaxrsClientRole.where {
            client == JaxrsClient.load(clientId) && role == JaxrsRole.load(roleId)
        }.get()
    }

    /**
     * Create an instance of this domain based on a client and a role.
     *
     * @param client
     * @param role
     * @return
     */
    static JaxrsClientRole create(JaxrsClient client, JaxrsRole role, boolean flush = false) {
        new JaxrsClientRole(client: client, role: role).save(flush: flush, insert: true)
    }

    /**
     * Remove an instance of this domain based on a client and a role.
     *
     * @param c
     * @param r
     * @return
     */
    static boolean remove(JaxrsClient c, JaxrsRole r, boolean flush = false) {

        int rowCount = JaxrsClientRole.where {
            client == JaxrsClient.load(c.id) &&
            role == JaxrsRole.load(r.id)
        }.deleteAll()

        rowCount > 0
    }

    /**
     * DB mapping.
     */
    static mapping = {
        id composite: ['client', 'role']
    }
}
