package org.grails.plugins.springsecurity.jaxrs.test.support

import grails.core.GrailsApplication
import grails.core.GrailsClass
import grails.plugin.springsecurity.ReflectionUtils
import org.grails.plugins.springsecurity.jaxrs.test.ClassSecurityResource
import org.grails.plugins.springsecurity.jaxrs.test.ResourceSecurityResource
import org.springframework.context.ApplicationContext
import org.springframework.security.access.vote.AuthenticatedVoter
import org.springframework.security.access.vote.RoleVoter
import org.springframework.security.web.FilterInvocation
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler
import spock.lang.Specification

import javax.servlet.http.HttpServletRequest

class JaxrsFilterInvocationSpec extends Specification {
    FilterInvocation filterInvocation
    HttpServletRequest httpServletRequest
    ApplicationContext applicationContext
    GrailsApplication grailsApplication
    GrailsClass classSecurityResourceGrailsClass
    GrailsClass resourceSecurityResourceGrailsClass

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

        classSecurityResourceGrailsClass = Mock(GrailsClass)
        classSecurityResourceGrailsClass.getClazz() >> ClassSecurityResource

        resourceSecurityResourceGrailsClass = Mock(GrailsClass)
        resourceSecurityResourceGrailsClass.getClazz() >> ResourceSecurityResource
    }
}
