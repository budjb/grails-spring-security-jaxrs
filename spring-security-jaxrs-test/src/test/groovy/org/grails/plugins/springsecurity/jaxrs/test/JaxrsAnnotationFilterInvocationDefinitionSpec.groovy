/*
 * Copyright 2015 Bud Byrd
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
package org.grails.plugins.springsecurity.jaxrs.test

import grails.core.GrailsClass
import org.grails.plugins.springsecurity.jaxrs.JaxrsAnnotationFilterInvocationDefinition
import org.grails.plugins.springsecurity.jaxrs.test.support.JaxrsFilterInvocationSpec
import org.springframework.security.access.ConfigAttribute
import spock.lang.Unroll

class JaxrsAnnotationFilterInvocationDefinitionSpec extends JaxrsFilterInvocationSpec {
    JaxrsAnnotationFilterInvocationDefinition jaxrsAnnotationFilterInvocationDefinition

    def setup() {
        jaxrsAnnotationFilterInvocationDefinition = new JaxrsAnnotationFilterInvocationDefinition()
        jaxrsAnnotationFilterInvocationDefinition.rejectIfNoRule = true
        jaxrsAnnotationFilterInvocationDefinition.allow404 = true
        jaxrsAnnotationFilterInvocationDefinition.initialize([classSecurityResourceGrailsClass, resourceSecurityResourceGrailsClass] as GrailsClass[])
    }

    @Unroll
    def 'Using the class security resource, ensure that "#method #path" returns security rule "#result"'() {
        setup:
        httpServletRequest.getRequestURI() >> path
        httpServletRequest.getContextPath() >> 'https://example.com'
        httpServletRequest.getMethod() >> method

        when:
        Collection<ConfigAttribute> results = jaxrsAnnotationFilterInvocationDefinition.getAttributes(filterInvocation)

        then:
        if (result == null) {
            assert results == null
        }
        else {
            assert results.size() == 1
            assert results[0].attribute == result
        }

        where:
        path                                               | method || result
        'https://example.com/api/class_security'           | 'GET'  || 'ROLE_READONLY'
        'https://example.com/api/class_security/anonymous' | 'GET'  || 'IS_AUTHENTICATED_ANONYMOUSLY'
        'https://example.com/api/class_security/override'  | 'GET'  || 'ROLE_USER'
    }

    @Unroll
    def 'Using the resource security resource, ensure that "#method #path" returns security rule "#result"'() {
        setup:
        httpServletRequest.getRequestURI() >> path
        httpServletRequest.getContextPath() >> 'https://example.com'
        httpServletRequest.getMethod() >> method

        when:
        Collection<ConfigAttribute> results = jaxrsAnnotationFilterInvocationDefinition.getAttributes(filterInvocation)

        then:
        if (result == null) {
            assert results == null
        }
        else {
            assert results.size() == 1
            assert results[0].attribute == result
        }

        where:
        path                                                  | method || result
        'https://example.com/api/resource_security'           | 'GET'  || 'ROLE_USER'
        'https://example.com/api/resource_security/anonymous' | 'GET'  || 'IS_AUTHENTICATED_ANONYMOUSLY'
        'https://example.com/api/resource_security/norule'    | 'GET'  || '_DENY_'
    }

    @Unroll
    def 'When rejectIfNoRule == #rejectIfNoRule and allow404 == #allow404, the security rule for an undefined resource is "#rule"'() {
        setup:
        httpServletRequest.getRequestURI() >> 'https://example.com/api/undefined_resource'
        httpServletRequest.getContextPath() >> 'https://example.com'
        httpServletRequest.getMethod() >> 'GET'

        jaxrsAnnotationFilterInvocationDefinition.rejectIfNoRule = rejectIfNoRule
        jaxrsAnnotationFilterInvocationDefinition.allow404 = allow404

        when:
        Collection<ConfigAttribute> results = jaxrsAnnotationFilterInvocationDefinition.getAttributes(filterInvocation)

        then:
        if (rule == null) {
            assert results == null
        }
        else {
            assert results.size() == 1
            assert results[0].attribute == rule
        }

        where:
        rejectIfNoRule | allow404 || rule
        false          | false    || null
        true           | false    || '_DENY_'
        false          | true     || null
        true           | true     || 'IS_AUTHENTICATED_ANONYMOUSLY'
    }
}
