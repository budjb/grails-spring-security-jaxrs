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
import com.budjb.jaxrs.security.JaxrsRequestmapFilterInvocationDefinition
import com.budjb.jaxrs.security.ObjectDefinitionSourceRegistry
import grails.plugin.springsecurity.SpringSecurityUtils
import org.apache.log4j.Logger
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor
import org.springframework.security.web.context.NullSecurityContextRepository

class SpringSecurityJaxrsGrailsPlugin {
    /**
     * Project version.
     */
    def version = '0.5.8'

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
    def description = 'Enables spring security support for the jax-rs plugin.'

    /**
     * Link to documentation.
     */
    def documentation = 'http://budjb.github.io/grails-jaxrs-security/doc/manual'

    /**
     * Project license.
     */
    def license = 'APACHE'

    /**
     * Issue tracker.
     */
    def issueManagement = [system: 'GITHUB', url: 'https://github.com/budjb/grails-jaxrs-secured/issues']

    /**
     * SCM.
     */
    def scm = [url: 'https://github.com/budjb/grails-jaxrs-secured']

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
     * Logger.
     */
    Logger log = Logger.getLogger('com.budjb.jaxrs.security.SpringSecurityJaxrsGrailsPlugin')

    def doWithSpring = {
        def conf = SpringSecurityUtils.securityConfig
        if (!conf || !conf.active) {
            return
        }

        SpringSecurityUtils.loadSecondaryConfig 'DefaultJaxrsSecurityConfig'
        conf = SpringSecurityUtils.securityConfig


        'objectDefinitionRegistry'(ObjectDefinitionSourceRegistry) { bean ->
            if (conf.rejectIfNoRule instanceof Boolean) {
                rejectIfNoRule = conf.rejectIfNoRule
            }
        }

        'filterInvocationInterceptor'(FilterSecurityInterceptor) {
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

        // Get the configured security type
        String securityConfigType = SpringSecurityUtils.securityConfigType
        if (!(securityConfigType in ['Annotation', 'Requestmap', 'InterceptUrlMap'])) {
            securityConfigType = 'Annotation'
        }

        if (securityConfigType == 'Annotation') {
            'jaxrsObjectDefinitionSource'(JaxrsAnnotationFilterInvocationDefinition) {
                if (conf.rejectIfNoRule instanceof Boolean) {
                    rejectIfNoRule = conf.rejectIfNoRule
                }
                if (conf.jaxrs.allow404 instanceof Boolean) {
                    allow404 = conf.jaxrs.allow404
                }
            }
        }
        else if (securityConfigType == 'Requestmap') {
            'jaxrsObjectDefinitionSource'(JaxrsRequestmapFilterInvocationDefinition) {
                if (conf.rejectIfNoRule instanceof Boolean) {
                    rejectIfNoRule = conf.rejectIfNoRule
                }
                if (conf.jaxrs.allow404 instanceof Boolean) {
                    allow404 = conf.jaxrs.allow404
                }
            }
        }
        else if (securityConfigType == 'InterceptUrlMap') {
            'jaxrsObjectDefinitionSource'(JaxrsInterceptUrlMapFilterInvocationDefinition) {
                if (conf.rejectIfNoRule instanceof Boolean) {
                    rejectIfNoRule = conf.rejectIfNoRule
                }
                if (conf.jaxrs.allow404 instanceof Boolean) {
                    allow404 = conf.jaxrs.allow404
                }
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
            addControllerMethods resourceClass.metaClass, ctx
        }
    }

    def onChange = { event ->
        def conf = SpringSecurityUtils.securityConfig
        if (!conf || !conf.active) {
            return
        }

        if (event.source && application.isResourceClass(event.source)) {
            event.ctx.jaxrsObjectDefinitionSource.initialize(application.resourceClasses)

            addControllerMethods application.getResourceClass(event.source.name).metaClass, event.ctx
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

    private void addControllerMethods(MetaClass mc, ctx) {
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
