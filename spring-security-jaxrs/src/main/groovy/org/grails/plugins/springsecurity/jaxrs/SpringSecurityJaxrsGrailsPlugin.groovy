/*
 * Copyright 2014-2016 Bud Byrd
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
package org.grails.plugins.springsecurity.jaxrs

import grails.plugin.springsecurity.SpringSecurityUtils
import grails.plugins.Plugin
import groovy.util.logging.Slf4j
import org.springframework.security.core.context.SecurityContextHolder as SCH
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor
import org.springframework.security.web.context.NullSecurityContextRepository

@Slf4j
class SpringSecurityJaxrsGrailsPlugin extends Plugin {
    /**
     * Required grails version.
     */
    def grailsVersion = '3.0 > *'

    /**
     * Plugin title.
     */
    def title = 'JAX-RS Support for Security Security'

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
     * Project license.
     */
    def license = 'APACHE'

    /**
     * Link to documentation.
     */
    def documentation = 'http://budjb.github.io/grails-spring-security-jaxrs/doc/manual'

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
        "file:./grails-app/resources/**/*Resource.groovy",
        "file:./plugins/*/grails-app/resources/**/*Resource.groovy"
    ]

    /**
     * Load order.
     */
    def loadAfter = ['jaxrs', 'spring-security-core']

    /**
     * Developers who have contributed to the development of the plugin.
     */
    def developers = [
        [name: 'Donald Jackson', email: 'donald@ddj.co.za']
    ]

    /**
     * Register Spring beans.
     *
     * @return
     */
    @Override
    Closure doWithSpring() {
        { ->
            def conf = SpringSecurityUtils.securityConfig
            if (!conf || !conf.active) {
                return
            }

            log.info "Configuring Spring Security for JAX-RS "

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
    }

    @Override
    void doWithApplicationContext() {
        def conf = SpringSecurityUtils.securityConfig
        if (!conf || !conf.active) {
            return
        }

        applicationContext.jaxrsObjectDefinitionSource.initialize(grailsApplication.resourceClasses)

        applicationContext.objectDefinitionRegistry.register(applicationContext.objectDefinitionSource)
        applicationContext.objectDefinitionRegistry.register(applicationContext.jaxrsObjectDefinitionSource)
    }

    @Override
    void doWithDynamicMethods() {
        def conf = SpringSecurityUtils.securityConfig
        if (!conf || !conf.active) {
            return
        }

        for (resourceClass in grailsApplication.resourceClasses) {
            addResourceMethods resourceClass.metaClass, applicationContext
        }
    }

    @Override
    void onChange(Map<String, Object> event) {
        def conf = SpringSecurityUtils.securityConfig
        if (!conf || !conf.active) {
            return
        }

        if (event.source && grailsApplication.isResourceClass(event.source)) {
            event.ctx.jaxrsObjectDefinitionSource.reset(grailsApplication.resourceClasses)

            addResourceMethods grailsApplication.getResourceClass(event.source.name).metaClass, event.ctx
        }
    }

    @Override
    void onConfigChange(Map<String, Object> event) {
        def conf = SpringSecurityUtils.securityConfig
        if (!conf || !conf.active) {
            return
        }

        SpringSecurityUtils.loadSecondaryConfig 'DefaultJaxrsSecurityConfig'

        event.ctx.jaxrsObjectDefinitionSource.reset(grailsApplication.resourceClasses)
    }

    private static void addResourceMethods(MetaClass mc, ctx) {
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
