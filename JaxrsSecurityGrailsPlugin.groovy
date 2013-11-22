/*
 * Copyright 2013 Bud Byrd
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
import org.grails.jaxrs.ResourceArtefactHandler
import org.apache.log4j.Logger

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
        "file:./grails-app/resources/**/*Resource.groovy",
        "file:./plugins/*/grails-app/resources/**/*Resource.groovy",
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
     * Bean configuration.
     */
    def doWithSpring = {
        'jaxrsSecurityContext'(JaxrsSecurityContext) { bean ->
            bean.autowire = 'byName'
        }
    }

    /**
     * Application context actions.
     */
    def doWithApplicationContext = { applicationContext ->
        reloadJaxrsSecurityContext(applicationContext.getBean('jaxrsSecurityContext'))
    }

    /**
     * Change event on watched resources.
     */
    def onChange = { event ->
        if (!event.ctx) {
            return
        }

        if (application.isArtefactOfType(ResourceArtefactHandler.TYPE, event.source)) {
            reloadJaxrsSecurityContext(event.ctx.getBean('jaxrsSecurityContext'))
        }
    }

    /**
     * Configuration change event.
     */
    def onConfigChange = { event ->
        reloadJaxrsSecurityContext(event.ctx.getBean('jaxrsSecurityContext'))
    }

    /**
     * Reloads the JaxrsSecurityContext.
     *
     * @param context
     * @return
     */
    def reloadJaxrsSecurityContext(JaxrsSecurityContext context) {
        context.initialize()
    }
}
