package org.grails.plugins.springsecurity.jaxrs.test

import com.sun.jersey.api.client.Client
import com.sun.jersey.api.client.ClientResponse
import geb.spock.GebSpec
import grails.test.mixin.integration.Integration
import spock.lang.Unroll

@Integration
class ClassSecurityResourceSpec extends GebSpec {
    @Unroll
    def 'Validate that a request to #method #endpoint with role #role returns HTTP status #status'() {
        setup:
        def client = Client.create().resource("${browser.baseUrl}${endpoint}")

        if (role) {
            client = client.header('role', role)
        }

        when:
        ClientResponse response = client.method(method.toString(), ClientResponse)

        then:
        response.status == status

        where:
        endpoint      | method   | role            || status
        '/api/shared' | 'GET'    | null            || 401
        '/api/shared' | 'GET'    | 'ROLE_READONLY' || 200
        '/api/shared' | 'GET'    | 'ROLE_USER'     || 403

        '/api/shared' | 'POST'   | null            || 401
        '/api/shared' | 'POST'   | 'ROLE_READONLY' || 403
        '/api/shared' | 'POST'   | 'ROLE_USER'     || 200

        '/api/shared' | 'PUT'    | null            || 200
        '/api/shared' | 'PUT'    | 'ROLE_READONLY' || 200
        '/api/shared' | 'PUT'    | 'ROLE_USER'     || 200

        '/api/shared' | 'DELETE' | null            || 401
        '/api/shared' | 'DELETE' | 'ROLE_READONLY' || 403
        '/api/shared' | 'DELETE' | 'ROLE_USER'     || 403


    }

    @Unroll
    def 'Validate that a request to #endpoint with role #role returns HTTP status #status'() {
        setup:
        def client = Client.create().resource("${browser.baseUrl}${endpoint}")

        if (role) {
            client = client.header('role', role)
        }

        when:
        ClientResponse response = client.get(ClientResponse)

        then:
        response.status == status

        where:
        endpoint                           | role            || status
        '/api/class_security'              | null            || 401
        '/api/class_security'              | 'ROLE_READONLY' || 200
        '/api/class_security'              | 'ROLE_USER'     || 403

        '/api/class_security/anonymous'    | null            || 200
        '/api/class_security/anonymous'    | 'ROLE_READONLY' || 200
        '/api/class_security/anonymous'    | 'ROLE_USER'     || 200

        '/api/class_security/override'     | null            || 401
        '/api/class_security/override'     | 'ROLE_READONLY' || 403
        '/api/class_security/override'     | 'ROLE_USER'     || 200

        '/api/resource_security'           | null            || 401
        '/api/resource_security'           | 'ROLE_USER'     || 200
        '/api/resource_security'           | 'ROLE_READONLY' || 403

        '/api/resource_security/anonymous' | null            || 200
        '/api/resource_security/anonymous' | 'ROLE_USER'     || 200
        '/api/resource_security/anonymous' | 'ROLE_READONLY' || 200

        '/api/resource_security/norule'    | null            || 401
        '/api/resource_security/norule'    | 'ROLE_USER'     || 403
        '/api/resource_security/norule'    | 'ROLE_READONLY' || 403
    }
}
