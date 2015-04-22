/*
 * Copyright 2014-2015 Bud Byrd
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
import com.budjb.jaxrs.security.JaxrsAnnotationFilterInvocationDefinition
import com.budjb.jaxrs.security.JaxrsInterceptUrlMapFilterInvocationDefinition
import com.budjb.jaxrs.security.JaxrsRequestMapFilterInvocationDefinition
import com.budjb.jaxrs.security.ObjectDefinitionSourceRegistry
import grails.plugin.springsecurity.SpringSecurityUtils
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.security.core.context.SecurityContextHolder as SCH
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor
import org.springframework.security.web.context.NullSecurityContextRepository

class SpringSecurityJaxrsGrailsPlugin {
    /**
     * Project version.
     */
    def version = '1.0.2'

    /**
     * Required grails version.
     */
    def grailsVersion = '2.3 > *'

    /**
     * Plugin title.
     */
    def title = 'Jaxrs Support for Security Security'

    /**
     * Author name.
     */
    def author = 'Bud Byrd'

    /**
     * Author email address.
     */
    def authorEmail = 'bud.byrd@gmail.com'

    /**
     * Plugin description.
     */
    def description = 'Enables Spring Security support for the JAX-RS plugin.'

    /**
     * Link to documentation.
     */
    def documentation = 'http://budjb.github.io/grails-spring-security-jaxrs/doc/manual'

    /**
     * Project license.
     */
    def license = 'APACHE'

    /**
     * Issue tracker.
     */
    def issueManagement = [url: 'https://github.com/budjb/grails-spring-security-jaxrs/issues']

    /**
     * SCM.
     */
    def scm = [url: 'https://github.com/budjb/grails-spring-security-jaxrs']

    /**
     * Files to watch for reloads.
     */
    def watchedResources = [
        "file:./grails-app/resources/**Resource.groovy",
        "file:./plugins/*/grails-app/resources/**Resource.groovy",
    ]

    /**
     * Load order.
     */
    def loadAfter = ['jaxrs', 'spring-security-core']

    /**
     * Excluded files.
     */
    def pluginExcludes = [
        'grails-app/controllers/**',
        'grails-app/resources/**',
        'src/groovy/com/budjb/jaxrs/security/test/**',
        'src/docs/**'
    ]

    def doWithSpring = {
        def conf = SpringSecurityUtils.securityConfig
        if (!conf || !conf.active) {
            return
        }

        SpringSecurityUtils.loadSecondaryConfig 'DefaultJaxrsSecurityConfig'
        conf = SpringSecurityUtils.securityConfig

        objectDefinitionRegistry(ObjectDefinitionSourceRegistry) {
            if (conf.rejectIfNoRule instanceof Boolean) {
                rejectIfNoRule = conf.rejectIfNoRule
            }
        }

        filterInvocationInterceptor(FilterSecurityInterceptor) {
            authenticationManager = ref('authenticationManager')
            accessDecisionManager = ref('accessDecisionManager')
            securityMetadataSource = ref('objectDefinitionRegistry')
            runAsManager = ref('runAsManager')
            afterInvocationManager = ref('afterInvocationManager')
            alwaysReauthenticate = conf.fii.alwaysReauthenticate // false
            rejectPublicInvocations = conf.fii.rejectPublicInvocations // true
            validateConfigAttributes = conf.fii.validateConfigAttributes // true
            publishAuthorizationSuccess = conf.fii.publishAuthorizationSuccess // false
            observeOncePerRequest = conf.fii.observeOncePerRequest // true
        }

        Class filterInvocationDefinitionClass
        switch (SpringSecurityUtils.securityConfigType) {
            case 'Requestmap':
                filterInvocationDefinitionClass = JaxrsRequestMapFilterInvocationDefinition
                break

            case 'InterceptUrlMap':
                filterInvocationDefinitionClass = JaxrsInterceptUrlMapFilterInvocationDefinition
                break

            default:
                filterInvocationDefinitionClass = JaxrsAnnotationFilterInvocationDefinition
        }

        jaxrsObjectDefinitionSource(filterInvocationDefinitionClass) {
            if (conf.rejectIfNoRule instanceof Boolean) {
                rejectIfNoRule = conf.rejectIfNoRule
            }
            if (conf.jaxrs.allow404 instanceof Boolean) {
                allow404 = conf.jaxrs.allow404
            }
        }

        if (conf.jaxrs.disableSessions instanceof Boolean && conf.jaxrs.disableSessions) {
            securityContextRepository(NullSecurityContextRepository)
        }
    }

    def doWithApplicationContext = { ctx ->
        def conf = SpringSecurityUtils.securityConfig
        if (!conf || !conf.active) {
            return
        }

        ctx.jaxrsObjectDefinitionSource.initialize(application.resourceClasses)

        ctx.objectDefinitionRegistry.register(ctx.objectDefinitionSource)
        ctx.objectDefinitionRegistry.register(ctx.jaxrsObjectDefinitionSource)
    }

    def doWithDynamicMethods = { ctx ->
        def conf = SpringSecurityUtils.securityConfig
        if (!conf || !conf.active) {
            return
        }

        for (resourceClass in application.resourceClasses) {
            addResourceMethods resourceClass.metaClass, ctx
        }
    }

    def onChange = { event ->
        def conf = SpringSecurityUtils.securityConfig
        if (!conf || !conf.active) {
            return
        }

        if (event.source && application.isResourceClass(event.source)) {
            event.ctx.jaxrsObjectDefinitionSource.initialize(application.resourceClasses)

            addResourceMethods application.getResourceClass(event.source.name).metaClass, event.ctx
        }
    }

    def onConfigChange = { event ->
        def conf = SpringSecurityUtils.securityConfig
        if (!conf || !conf.active) {
            return
        }

        SpringSecurityUtils.loadSecondaryConfig 'DefaultJaxrsSecurityConfig'

        event.ctx.jaxrsObjectDefinitionSource.initialize(application.resourceClasses)
    }

    private void addResourceMethods(MetaClass mc, ctx) {
        if (!mc.respondsTo(null, 'getPrincipal')) {
            mc.getPrincipal = { -> SCH.context?.authentication?.principal }
        }

        if (!mc.respondsTo(null, 'isLoggedIn')) {
            mc.isLoggedIn = { -> ctx.springSecurityService.isLoggedIn() }
        }

        if (!mc.respondsTo(null, 'getAuthenticatedUser')) {
            mc.getAuthenticatedUser = { ->
                if (!ctx.springSecurityService.isLoggedIn()) {
                    return null
                }
                String userClassName = SpringSecurityUtils.securityConfig.userLookup.userDomainClassName
                def dc = ctx.grailsApplication.getDomainClass(userClassName)
                if (!dc) {
                    throw new IllegalArgumentException("The specified user domain class '$userClassName' is not a domain class")
                }
                Class User = dc.clazz
                String usernamePropertyName = SpringSecurityUtils.securityConfig.userLookup.usernamePropertyName
                User.findWhere((usernamePropertyName): SCH.context.authentication.principal.username)
            }
        }
    }
}
