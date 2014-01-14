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
import com.budjb.jaxrs.security.JaxrsSecurityContext
import com.budjb.jaxrs.security.JaxrsAuthenticationProviderArtefactHandler
import com.budjb.jaxrs.security.GrailsJaxrsAuthenticationProviderClass
import com.budjb.jaxrs.security.provider.HeaderApiKeyAuthenticationProvider
import com.budjb.jaxrs.security.provider.QueryApiKeyAuthenticationProvider
import org.grails.jaxrs.ResourceArtefactHandler
import org.apache.log4j.Logger

import org.codehaus.groovy.grails.commons.GrailsApplication
import org.codehaus.groovy.grails.commons.GrailsClass

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
        "file:./grails-app/jaxrs-security-auth/**AuthenticationProvider.groovy",
        "file:./plugins/*/grails-app/jaxrs-security-auth/**AuthenticationProvider.groovy"
    ]

    /**
     * Load order.
     */
    def loadAfter = ['jaxrs']

    /**
     * Logger.
     */
    Logger log = Logger.getLogger('com.budjb.jaxrs.security.JaxrsSecurityGrailsPlugin')

    /**
     * Customer artefacts.
     */
    def artefacts = [
        new JaxrsAuthenticationProviderArtefactHandler()
    ]

    /**
     * Bean configuration.
     */
    def doWithSpring = {
        // Built-in providers
        "${HeaderApiKeyAuthenticationProvider.name}"(HeaderApiKeyAuthenticationProvider) { bean ->
            bean.scope = 'singleton'
            bean.autowire = true
        }
        "${QueryApiKeyAuthenticationProvider.name}"(QueryApiKeyAuthenticationProvider) { bean ->
            bean.scope = 'singleton'
            bean.autowire = true
        }

        // Register client providers
        application.jaxrsAuthenticationProviderClasses.each { GrailsClass clazz ->
            "${clazz.fullName}"(clazz.clazz) { bean ->
                bean.scope = 'singleton'
                bean.autowire = true
            }
        }

        // Security context
        'jaxrsSecurityContext'(JaxrsSecurityContext) { bean ->
            bean.autowire = 'byName'
        }
    }

    /**
     * Application context actions.
     */
    def doWithApplicationContext = { applicationContext ->
        reloadJaxrsSecurityContext(application, applicationContext.getBean('jaxrsSecurityContext'))
    }

    /**
     * Change event on watched resources.
     */
    def onChange = { event ->
        if (!event.ctx) {
            return
        }

        if (application.isArtefactOfType(ResourceArtefactHandler.TYPE, event.source)) {
            reloadJaxrsSecurityContext(application, event.ctx.getBean('jaxrsSecurityContext'))
        }
        else if (application.isArtefactOfType(JaxrsAuthenticationProviderArtefactHandler.TYPE, event.source)) {
            GrailsJaxrsAuthenticationProviderClass converterClass = application.addArtefact(JaxrsAuthenticationProviderArtefactHandler.TYPE, event.source)
            beans {
                "${converterClass.propertyName}"(converterClass.clazz) { bean ->
                    bean.scope = 'singleton'
                    bean.autowire = true
                }
            }.registerBeans(event.ctx)

            reloadJaxrsSecurityContext(application, event.ctx.getBean('jaxrsSecurityContext'))
        }
    }

    /**
     * Configuration change event.
     */
    def onConfigChange = { event ->
        reloadJaxrsSecurityContext(application, event.ctx.getBean('jaxrsSecurityContext'))
    }

    /**
     * Reloads the JaxrsSecurityContext.
     *
     * @param context
     * @return
     */
    def reloadJaxrsSecurityContext(GrailsApplication application, JaxrsSecurityContext context) {
        context.initialize()

        application.jaxrsAuthenticationProviderClasses.each { GrailsClass clazz ->
            context.registerAuthenticationProvider(application.mainContext.getBean(clazz.fullName))
        }

        context.registerAuthenticationProvider(application.mainContext.getBean(HeaderApiKeyAuthenticationProvider.name))
        context.registerAuthenticationProvider(application.mainContext.getBean(QueryApiKeyAuthenticationProvider.name))
    }
}
