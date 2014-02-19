/*
 * Copyright 2014 Bud Byrd
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
import org.grails.jaxrs.ResourceArtefactHandler
import org.apache.log4j.Logger

import org.codehaus.groovy.grails.commons.GrailsApplication
import org.codehaus.groovy.grails.commons.GrailsClass

import com.budjb.jaxrs.security.JaxrsAnnotationFilterInvocationDefinition

import grails.plugin.springsecurity.SpringSecurityUtils

class JaxrsSecurityGrailsPlugin {
    /**
     * Project version.
     */
    def version = '0.4'

    /**
     * Maven group.
     */
    def group = 'com.rackspace.rvi'

    /**
     * Required grails version.
     */
    def grailsVersion = '2.0 > *'

    /**
     * Plugin title.
     */
    def title = 'Jaxrs Security'

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
    def description = 'Provides a security layer on top of the jax-rs plugin.'

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
    Logger log = Logger.getLogger('com.budjb.jaxrs.security.JaxrsSecurityGrailsPlugin')

    /**
     * Bean configuration.
     */
    def doWithSpring = {
        // Get the spring security config
        def conf = SpringSecurityUtils.securityConfig

        // Get the configured security type
        String securityConfigType = SpringSecurityUtils.securityConfigType
        if (!(securityConfigType in ['Annotation', 'Requestmap', 'InterceptUrlMap'])) {
            securityConfigType = 'Annotation'
        }

        if (securityConfigType == 'Annotation') {
            objectDefinitionSource(JaxrsAnnotationFilterInvocationDefinition) {
                application = ref('grailsApplication')
                grailsUrlConverter = ref('grailsUrlConverter')
                responseMimeTypesApi = ref('responseMimeTypesApi')
                boolean lowercase = conf.controllerAnnotations.lowercase // true
                if (conf.rejectIfNoRule instanceof Boolean) {
                    rejectIfNoRule = conf.rejectIfNoRule
                }
            }
        }
        /*
        else if (securityConfigType == 'Requestmap') {
            objectDefinitionSource(RequestmapFilterInvocationDefinition) {
                if (conf.rejectIfNoRule instanceof Boolean) {
                    rejectIfNoRule = conf.rejectIfNoRule
                }
            }
        }
        else if (securityConfigType == 'InterceptUrlMap') {
            objectDefinitionSource(InterceptUrlMapFilterInvocationDefinition) {
                if (conf.rejectIfNoRule instanceof Boolean) {
                    rejectIfNoRule = conf.rejectIfNoRule
                }
            }
        }
        */
    }

    /**
     * Change event on watched resources.
     */
    def onChange = { event ->
        def conf = SpringSecurityUtils.securityConfig
        if (!conf || !conf.active) {
            return
        }

        if (event.source && application.isResourceClass(event.source)) {

            if (SpringSecurityUtils.securityConfigType == 'Annotation') {
                initializeFromAnnotations event.ctx, conf, application
            }
        }
    }
    private void initializeFromAnnotations(ctx, conf, application) {
        JaxrsAnnotationFilterInvocationDefinition afid = ctx.objectDefinitionSource
        afid.initialize conf.controllerAnnotations.staticRules,
            ctx.grailsUrlMappingsHolder, application.controllerClasses
    }
}
