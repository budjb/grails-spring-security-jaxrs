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
