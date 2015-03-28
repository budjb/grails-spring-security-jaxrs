package com.budjb.jaxrs.security

import com.budjb.jaxrs.security.test.JaxrsFilterInvocationTest
import com.budjb.jaxrs.test.ClassSecurityResource
import com.budjb.jaxrs.test.ResourceSecurityResource
import org.codehaus.groovy.grails.commons.GrailsClass
import org.springframework.security.access.ConfigAttribute
import spock.lang.Unroll

class JaxrsAnnotationFilterInvocationDefinitionSpec extends JaxrsFilterInvocationTest {
    JaxrsAnnotationFilterInvocationDefinition jaxrsAnnotationFilterInvocationDefinition

    def setup() {
        GrailsClass classSecurityResourceGrailsClass = Mock(GrailsClass)
        classSecurityResourceGrailsClass.getClazz() >> ClassSecurityResource

        GrailsClass resourceSecurityResourceGrailsClass = Mock(GrailsClass)
        resourceSecurityResourceGrailsClass.getClazz() >> ResourceSecurityResource

        jaxrsAnnotationFilterInvocationDefinition = new JaxrsAnnotationFilterInvocationDefinition()
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
        'https://example.com/api/class_security'           | 'GET'  || 'ROLE_USER'
        'https://example.com/api/class_security/anonymous' | 'GET'  || 'IS_AUTHENTICATED_ANONYMOUSLY'
        'https://example.com/api/class_security/inherit'   | 'GET'  || 'ROLE_READONLY'
        'https://example.com/api/class_security/undefined' | 'GET'  || null
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
        'https://example.com/api/resource_security/norule'    | 'GET'  || null
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
        rejectIfNoRule  | allow404  || rule
        false           | false     || null
        true            | false     || '_DENY_'
        false           | true      || null
        true            | true      || 'IS_AUTHENTICATED_ANONYMOUSLY'
    }
}
