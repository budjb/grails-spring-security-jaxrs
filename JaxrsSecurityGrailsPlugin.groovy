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

class JaxrsSecurityGrailsPlugin {
    def version = '0.1'
    def grailsVersion = '2.0 > *'
    def title = 'Jaxrs Security'
    def author = 'Bud Byrd'
    def authorEmail = 'bud.byrd@gmail.com'
    def description = 'Provides a SpringSecurity-like security layer on top of the jax-rs plugin.'
    def documentation = 'http://budjb.github.io/grails-jaxrs-security/doc/manual'
    def license = 'APACHE'
    def issueManagement = [system: 'GITHUB', url: 'https://github.com/budjb/grails-jaxrs-secured/issues']
    def scm = [url: 'https://github.com/budjb/grails-jaxrs-secured']

    def doWithSpring = {
        'jaxrsSecurityContext'(JaxrsSecurityContext) { bean ->
            bean.autowire = 'byName'
        }
    }

    def doWithApplicationContext = { applicationContext ->
        reloadJaxrsSecurityContext(applicationContext.getBean('jaxrsSecurityContext'))
    }

    def onChange = { event ->
        if (application.isArtefactOfType(ResourceArtefactHandler.TYPE, event.source)) {
            reloadJaxrsSecurityContext(event.ctx.getBean('jaxrsSecurityContext'))
        }
    }

    def onConfigChange = { event ->
        reloadJaxrsSecurityContext(event.ctx.getBean('jaxrsSecurityContext'))
    }

    def reloadJaxrsSecurityContext(JaxrsSecurityContext context) {
        context.initialize()
    }
}
