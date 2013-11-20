

import com.budjb.jaxrs.security.JaxrsSecurityContext
import com.budjb.jaxrs.security.exception.ForbiddenClientException
import com.budjb.jaxrs.security.exception.UnauthorizedClientException
import org.apache.log4j.Logger

class JaxrsFilters {
    /**
     * Logger
     */
    Logger log = Logger.getLogger('com.budjb.jaxrs.security.JaxrsFilters')

    /**
     * Security context holder
     */
    JaxrsSecurityContext jaxrsSecurityContext

    def filters = {
        all(controller: 'jaxrs', action: '*') {
            before = {
                try {
                    jaxrsSecurityContext.process(request)
                }
                catch (UnauthorizedClientException e) {
                    render template: '/jaxrs/unauthorized', model: [message: e.message], status: 401
                    return false
                }
                catch(ForbiddenClientException e) {
                    render template: '/jaxrs/forbidden', model: [message: e.message], status: 403
                    return false
                }
                catch (Exception e) {
                    log.debug("unexpected error occurred", e)
                    render template: '/jaxrs/error', model: [message: e.message], status: 500
                    return false
                }
            }
        }
    }
}
