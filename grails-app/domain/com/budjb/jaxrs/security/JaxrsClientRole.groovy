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
