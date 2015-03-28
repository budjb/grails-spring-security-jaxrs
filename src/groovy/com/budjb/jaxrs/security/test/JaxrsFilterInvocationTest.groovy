package com.budjb.jaxrs.security.test

import grails.plugin.springsecurity.ReflectionUtils
import org.codehaus.groovy.grails.commons.GrailsApplication
import org.springframework.context.ApplicationContext
import org.springframework.security.access.vote.AuthenticatedVoter
import org.springframework.security.access.vote.RoleVoter
import org.springframework.security.web.FilterInvocation
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler
import spock.lang.Specification

import javax.servlet.http.HttpServletRequest

class JaxrsFilterInvocationTest extends Specification {
    FilterInvocation filterInvocation
    HttpServletRequest httpServletRequest
    ApplicationContext applicationContext
    GrailsApplication grailsApplication

    def setup() {
        applicationContext = Mock(ApplicationContext)
        applicationContext.getBean('roleVoter') >> new RoleVoter()
        applicationContext.getBean('webExpressionHandler') >> new DefaultWebSecurityExpressionHandler()
        applicationContext.getBean('authenticatedVoter') >> new AuthenticatedVoter()

        grailsApplication = Mock(GrailsApplication)
        grailsApplication.getMainContext() >> applicationContext

        ReflectionUtils.application = grailsApplication

        httpServletRequest = Mock(HttpServletRequest)

        filterInvocation = Mock(FilterInvocation)
        filterInvocation.getHttpRequest() >> httpServletRequest
    }
}
