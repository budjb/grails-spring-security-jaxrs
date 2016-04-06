package org.grails.plugins.spring.security.jaxrs

import grails.plugin.springsecurity.web.access.intercept.AbstractFilterInvocationDefinition
import org.grails.plugins.spring.security.jaxrs.support.JaxrsFilterInvocationTest
import org.springframework.security.access.ConfigAttribute

class ObjectDefinitionSourceRegistrySpec extends JaxrsFilterInvocationTest {
    ObjectDefinitionSourceRegistry objectDefinitionSourceRegistry
    JaxrsFilterInvocationDefinition jaxrsFilterInvocationDefinition
    AbstractFilterInvocationDefinition grailsFilterInvocationDefinition

    def setup() {
        grailsFilterInvocationDefinition = Mock(AbstractFilterInvocationDefinition)
        jaxrsFilterInvocationDefinition = Mock(JaxrsFilterInvocationDefinition)

        objectDefinitionSourceRegistry = new ObjectDefinitionSourceRegistry()
        objectDefinitionSourceRegistry.register(grailsFilterInvocationDefinition)
        objectDefinitionSourceRegistry.register(jaxrsFilterInvocationDefinition)
    }

    def 'When the Grails object definition source matches a request, the JAX-RS object definition source is not used'() {
        setup:
        httpServletRequest.getRequestURI() >> 'https://example.com/index/index'
        httpServletRequest.getContextPath() >> 'https://example.com'
        httpServletRequest.getMethod() >> 'GET'

        ConfigAttribute configAttribute = Mock(ConfigAttribute)
        configAttribute.getAttribute() >> 'ROLE_READONLY'

        grailsFilterInvocationDefinition.getAttributes(filterInvocation) >> [configAttribute]

        when:
        def result = objectDefinitionSourceRegistry.getAttributes(filterInvocation)

        then:
        result == [configAttribute]
        0 * jaxrsFilterInvocationDefinition._
    }

    def 'When the JAX-RS object definition source matches a request, the Grails object definition source checked first'() {
        setup:
        httpServletRequest.getRequestURI() >> 'https://example.com/api/index'
        httpServletRequest.getContextPath() >> 'https://example.com'
        httpServletRequest.getMethod() >> 'GET'

        ConfigAttribute configAttribute = Mock(ConfigAttribute)
        configAttribute.getAttribute() >> 'ROLE_READONLY'

        jaxrsFilterInvocationDefinition.getAttributes(filterInvocation) >> [configAttribute]

        when:
        def result = objectDefinitionSourceRegistry.getAttributes(filterInvocation)

        then:
        result == [configAttribute]
        1 * grailsFilterInvocationDefinition.getAttributes(filterInvocation)
    }

    def 'When no object definition sources matche a request, an empty list is returned'() {
        setup:
        httpServletRequest.getRequestURI() >> 'https://example.com/api/index'
        httpServletRequest.getContextPath() >> 'https://example.com'
        httpServletRequest.getMethod() >> 'GET'

        when:
        def result = objectDefinitionSourceRegistry.getAttributes(filterInvocation)

        then:
        result == []
        1 * jaxrsFilterInvocationDefinition.getAttributes(filterInvocation)
        1 * grailsFilterInvocationDefinition.getAttributes(filterInvocation)
    }
}
